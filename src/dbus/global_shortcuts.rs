// SPDX-License-Identifier: GPL-3.0-only
// https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.GlobalShortcuts.html

use cosmic_settings_config::shortcuts::Modifiers;
use futures_executor::ThreadPool;
use smithay::input::keyboard::ModifiersState;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::debug;
use xkbcommon::xkb::Keysym;
use zbus::{
    message::Header,
    names::{UniqueName, WellKnownName},
    object_server::SignalEmitter,
    zvariant::{OwnedValue, Value},
};

use super::name_owners::NameOwners;

static ALLOWED_NAMES: &'static [WellKnownName] = &[WellKnownName::from_static_str_unchecked(
    "org.freedesktop.impl.portal.desktop.cosmic",
)];

/// A global shortcut registered by a client
#[derive(Debug, Clone)]
pub struct GlobalShortcut {
    pub id: String,
    pub modifiers: Modifiers,
    pub keysym: Keysym,
    pub description: String,
}

/// A session holding shortcuts for a client
#[derive(Debug)]
struct Session {
    shortcuts: HashMap<String, GlobalShortcut>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            shortcuts: HashMap::new(),
        }
    }
}

#[derive(Debug, Default)]
struct Sessions(HashMap<String, Session>);

#[derive(Debug)]
pub struct GlobalShortcutsState {
    executor: ThreadPool,
    sessions: Arc<Mutex<Sessions>>,
    conn: Arc<OnceLock<zbus::Connection>>,
    name_owners: Arc<OnceLock<NameOwners>>,
    active_shortcuts: Mutex<HashSet<String>>,
}

impl GlobalShortcutsState {
    pub fn new(executor: &ThreadPool) -> Self {
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        let sessions_clone = sessions.clone();
        let conn_cell = Arc::new(OnceLock::new());
        let conn_cell_clone = conn_cell.clone();
        let name_owners_cell = Arc::new(OnceLock::new());
        let name_owners_cell_clone = name_owners_cell.clone();
        let executor_clone = executor.clone();
        executor.spawn_ok(async move {
            match serve(sessions_clone, &executor_clone).await {
                Ok((conn, name_owners)) => {
                    conn_cell_clone.set(conn).unwrap();
                    name_owners_cell_clone.set(name_owners).unwrap();
                }
                Err(err) => {
                    tracing::error!(
                        "Failed to serve `org.cosmic.compositor.GlobalShortcuts`: {err}"
                    );
                }
            }
        });
        Self {
            executor: executor.clone(),
            sessions,
            conn: conn_cell,
            name_owners: name_owners_cell,
            active_shortcuts: Mutex::new(HashSet::new()),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        Self {
            executor: futures_executor::ThreadPool::new().unwrap(),
            sessions: Arc::new(Mutex::new(Sessions::default())),
            conn: Arc::new(OnceLock::new()),
            name_owners: Arc::new(OnceLock::new()),
            active_shortcuts: Mutex::new(HashSet::new()),
        }
    }

    fn to_cosmic_mods(modifiers: &ModifiersState) -> Modifiers {
        Modifiers {
            ctrl: modifiers.ctrl,
            alt: modifiers.alt,
            shift: modifiers.shift,
            logo: modifiers.logo,
        }
    }

    pub fn has_shortcut_grab(&self, modifiers: &ModifiersState, keysym: Keysym) -> bool {
        self.find_shortcut(modifiers, keysym).is_some()
    }

    pub fn find_shortcut(&self, modifiers: &ModifiersState, keysym: Keysym) -> Option<String> {
        let cosmic_mods = Self::to_cosmic_mods(modifiers);
        self.sessions
            .lock()
            .unwrap()
            .0
            .values()
            .flat_map(|session| session.shortcuts.values())
            .find(|s| s.modifiers == cosmic_mods && s.keysym == keysym)
            .map(|s| s.id.clone())
    }

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    fn emit_activated(&self, shortcut_id: &str) {
        let Some(conn) = self.conn.get() else { return };
        let ctx = SignalEmitter::new(conn, "/org/cosmic/GlobalShortcuts").unwrap();
        let future = GlobalShortcutsInterface::activated(
            ctx, shortcut_id.to_string(), Self::now_micros(), HashMap::new()
        );
        self.executor.spawn_ok(async { let _ = future.await; });
    }

    fn emit_deactivated(&self, shortcut_id: &str) {
        let Some(conn) = self.conn.get() else { return };
        let ctx = SignalEmitter::new(conn, "/org/cosmic/GlobalShortcuts").unwrap();
        let future = GlobalShortcutsInterface::deactivated(
            ctx, shortcut_id.to_string(), Self::now_micros(), HashMap::new()
        );
        self.executor.spawn_ok(async { let _ = future.await; });
    }

    pub fn activate(&self, shortcut_id: &str) {
        self.active_shortcuts.lock().unwrap().insert(shortcut_id.to_string());
        self.emit_activated(shortcut_id);
    }

    pub fn deactivate_all(&self) {
        let ids: Vec<String> = self.active_shortcuts.lock().unwrap().drain().collect();
        for id in ids {
            self.emit_deactivated(&id);
        }
    }

    #[cfg(test)]
    fn active_shortcut_count(&self) -> usize {
        self.active_shortcuts.lock().unwrap().len()
    }

    /// Clear sessions if the portal is no longer connected
    pub fn refresh(&mut self) {
        if let Some(name_owners) = self.name_owners.get() {
            if !name_owners.any_name_present_no_poll(ALLOWED_NAMES) {
                self.sessions.lock().unwrap().0.clear();
                self.active_shortcuts.lock().unwrap().clear();
            }
        }
    }
}

struct GlobalShortcutsInterface {
    sessions: Arc<Mutex<Sessions>>,
    name_owners: NameOwners,
}

impl GlobalShortcutsInterface {
    async fn check_sender_allowed(&self, sender: &UniqueName<'_>) -> zbus::fdo::Result<()> {
        if self.name_owners.check_owner(sender, ALLOWED_NAMES).await {
            Ok(())
        } else {
            Err(zbus::fdo::Error::AccessDenied("Access denied".to_string()))
        }
    }
}

/// Shortcut description as sent over D-Bus
type ShortcutDesc = (String, HashMap<String, OwnedValue>);

#[zbus::interface(name = "org.cosmic.compositor.GlobalShortcuts")]
impl GlobalShortcutsInterface {
    /// Create a new session for global shortcuts
    async fn create_session(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        session_handle: String,
    ) -> zbus::fdo::Result<()> {
        if let Some(sender) = header.sender() {
            self.check_sender_allowed(sender).await?;
            let mut sessions = self.sessions.lock().unwrap();
            sessions.0.insert(session_handle.clone(), Session::default());
            debug!("created global shortcuts session: {}", session_handle);
        }
        Ok(())
    }

    /// Bind shortcuts to a session
    async fn bind_shortcuts(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        session_handle: String,
        shortcuts: Vec<ShortcutDesc>,
    ) -> zbus::fdo::Result<Vec<ShortcutDesc>> {
        if let Some(sender) = header.sender() {
            self.check_sender_allowed(sender).await?;
            let mut sessions = self.sessions.lock().unwrap();

            if let Some(session) = sessions.0.get_mut(&session_handle) {
                let mut bound_shortcuts = Vec::new();

                for (id, props) in shortcuts {
                    // Extract properties
                    let description = props
                        .get("description")
                        .and_then(|v| <&str>::try_from(v).ok())
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    let trigger_description = props
                        .get("trigger-description")
                        .and_then(|v| <&str>::try_from(v).ok())
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    // Parse trigger-description to extract modifiers and keysym
                    // Format is expected to be like "ctrl+alt+t" or just "F12"
                    let (modifiers, keysym) = parse_trigger_description(&trigger_description);

                    let shortcut = GlobalShortcut {
                        id: id.clone(),
                        modifiers,
                        keysym,
                        description: description.clone(),
                    };

                    session.shortcuts.insert(id.clone(), shortcut);

                    // Return the bound shortcut description
                    let mut result_props: HashMap<String, OwnedValue> = HashMap::new();
                    result_props.insert(
                        "description".to_string(),
                        Value::from(description).try_into().unwrap(),
                    );
                    result_props.insert(
                        "trigger-description".to_string(),
                        Value::from(trigger_description).try_into().unwrap(),
                    );
                    bound_shortcuts.push((id, result_props));
                }

                debug!(
                    "bound {} shortcuts to session {}",
                    bound_shortcuts.len(),
                    session_handle
                );
                return Ok(bound_shortcuts);
            }

            Err(zbus::fdo::Error::InvalidArgs(
                "Session not found".to_string(),
            ))
        } else {
            Err(zbus::fdo::Error::AccessDenied("No sender".to_string()))
        }
    }

    /// List shortcuts for a session
    async fn list_shortcuts(
        &self,
        #[zbus(header)] header: Header<'_>,
        session_handle: String,
    ) -> zbus::fdo::Result<Vec<ShortcutDesc>> {
        if let Some(sender) = header.sender() {
            self.check_sender_allowed(sender).await?;
            let sessions = self.sessions.lock().unwrap();

            if let Some(session) = sessions.0.get(&session_handle) {
                let shortcuts: Vec<ShortcutDesc> = session
                    .shortcuts
                    .values()
                    .map(|shortcut| {
                        let mut props: HashMap<String, OwnedValue> = HashMap::new();
                        props.insert(
                            "description".to_string(),
                            Value::from(shortcut.description.clone()).try_into().unwrap(),
                        );
                        props.insert(
                            "trigger-description".to_string(),
                            Value::from(format_trigger_description(
                                &shortcut.modifiers,
                                shortcut.keysym,
                            ))
                            .try_into()
                            .unwrap(),
                        );
                        (shortcut.id.clone(), props)
                    })
                    .collect();

                debug!(
                    "listed {} shortcuts for session {}",
                    shortcuts.len(),
                    session_handle
                );
                return Ok(shortcuts);
            }

            Err(zbus::fdo::Error::InvalidArgs(
                "Session not found".to_string(),
            ))
        } else {
            Err(zbus::fdo::Error::AccessDenied("No sender".to_string()))
        }
    }

    /// Close a session
    async fn close_session(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        session_handle: String,
    ) -> zbus::fdo::Result<()> {
        if let Some(sender) = header.sender() {
            self.check_sender_allowed(sender).await?;
            let mut sessions = self.sessions.lock().unwrap();
            sessions.0.remove(&session_handle);
            debug!("closed global shortcuts session: {}", session_handle);
        }
        Ok(())
    }

    /// Signal emitted when a shortcut is activated
    #[zbus(signal)]
    async fn activated(
        ctx: SignalEmitter<'_>,
        shortcut_id: String,
        timestamp: u64,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    /// Signal emitted when a shortcut is deactivated
    #[zbus(signal)]
    async fn deactivated(
        ctx: SignalEmitter<'_>,
        shortcut_id: String,
        timestamp: u64,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    /// Signal emitted when shortcuts changed
    #[zbus(signal)]
    async fn shortcuts_changed(
        ctx: SignalEmitter<'_>,
        session_handle: String,
    ) -> zbus::Result<()>;
}

/// Parse a trigger description string into modifiers and keysym
fn parse_trigger_description(desc: &str) -> (Modifiers, Keysym) {
    let mut modifiers = Modifiers::default();
    let mut keysym = Keysym::NoSymbol;

    let parts: Vec<&str> = desc.split('+').collect();
    for part in parts {
        let part_lower = part.to_lowercase();
        match part_lower.as_str() {
            "ctrl" | "control" => modifiers.ctrl = true,
            "alt" => modifiers.alt = true,
            "shift" => modifiers.shift = true,
            "super" | "logo" | "mod4" => modifiers.logo = true,
            _ => {
                // Try to parse as keysym
                keysym = xkbcommon::xkb::keysym_from_name(part, xkbcommon::xkb::KEYSYM_CASE_INSENSITIVE);
            }
        }
    }

    (modifiers, keysym)
}

fn format_trigger_description(modifiers: &Modifiers, keysym: Keysym) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(5);
    if modifiers.ctrl { parts.push("ctrl"); }
    if modifiers.alt { parts.push("alt"); }
    if modifiers.shift { parts.push("shift"); }
    if modifiers.logo { parts.push("super"); }

    let keysym_name = xkbcommon::xkb::keysym_get_name(keysym);
    if parts.is_empty() {
        keysym_name
    } else {
        format!("{}+{}", parts.join("+"), keysym_name)
    }
}

async fn serve(
    sessions: Arc<Mutex<Sessions>>,
    executor: &ThreadPool,
) -> zbus::Result<(zbus::Connection, NameOwners)> {
    let conn = zbus::Connection::session().await?;
    let name_owners = NameOwners::new(&conn, executor).await?;
    let global_shortcuts = GlobalShortcutsInterface {
        sessions,
        name_owners: name_owners.clone(),
    };
    conn.object_server()
        .at("/org/cosmic/GlobalShortcuts", global_shortcuts)
        .await?;
    conn.request_name("org.cosmic.compositor.GlobalShortcuts")
        .await?;
    Ok((conn, name_owners))
}

#[cfg(test)]
mod tests {
    use super::{
        format_trigger_description, parse_trigger_description, GlobalShortcut,
        GlobalShortcutsState,
    };
    use cosmic_settings_config::shortcuts::Modifiers;
    use smithay::input::keyboard::ModifiersState;
    use xkbcommon::xkb::Keysym;

    const CTRL: Modifiers = Modifiers { ctrl: true, alt: false, shift: false, logo: false };
    const CTRL_ALT: Modifiers = Modifiers { ctrl: true, alt: true, shift: false, logo: false };
    const ALL: Modifiers = Modifiers { ctrl: true, alt: true, shift: true, logo: true };
    const NONE: Modifiers = Modifiers { ctrl: false, alt: false, shift: false, logo: false };

    #[test]
    fn parse_single_key() {
        assert_eq!(parse_trigger_description("t"), (NONE, Keysym::t));
        assert_eq!(parse_trigger_description("F12"), (NONE, Keysym::F12));
    }

    #[test]
    fn parse_modifiers() {
        assert_eq!(parse_trigger_description("ctrl+t"), (CTRL, Keysym::t));
        assert_eq!(parse_trigger_description("control+t"), (CTRL, Keysym::t));
        assert_eq!(parse_trigger_description("alt+t").0.alt, true);
        assert_eq!(parse_trigger_description("shift+t").0.shift, true);
        assert_eq!(parse_trigger_description("super+t").0.logo, true);
        assert_eq!(parse_trigger_description("logo+t").0.logo, true);
        assert_eq!(parse_trigger_description("mod4+t").0.logo, true);
    }

    #[test]
    fn parse_multiple_modifiers() {
        assert_eq!(parse_trigger_description("ctrl+alt+t"), (CTRL_ALT, Keysym::t));
        assert_eq!(parse_trigger_description("alt+ctrl+t"), (CTRL_ALT, Keysym::t));
        assert_eq!(parse_trigger_description("ctrl+alt+shift+super+t"), (ALL, Keysym::t));
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(parse_trigger_description("CTRL+T"), (CTRL, Keysym::t));
        assert_eq!(parse_trigger_description("Ctrl+Alt+T"), (CTRL_ALT, Keysym::t));
    }

    #[test]
    fn parse_empty_and_invalid() {
        assert_eq!(parse_trigger_description(""), (NONE, Keysym::NoSymbol));
        assert_eq!(parse_trigger_description("ctrl+unknownkey"), (CTRL, Keysym::NoSymbol));
    }

    #[test]
    fn format_trigger() {
        assert_eq!(format_trigger_description(&NONE, Keysym::t), "t");
        assert_eq!(format_trigger_description(&CTRL, Keysym::t), "ctrl+t");
        assert_eq!(format_trigger_description(&CTRL_ALT, Keysym::t), "ctrl+alt+t");
        assert_eq!(format_trigger_description(&ALL, Keysym::t), "ctrl+alt+shift+super+t");
    }

    #[test]
    fn roundtrip() {
        for (mods, key) in [(CTRL, Keysym::t), (CTRL_ALT, Keysym::F1), (ALL, Keysym::space)] {
            let formatted = format_trigger_description(&mods, key);
            assert_eq!(parse_trigger_description(&formatted), (mods, key));
        }
    }

    #[test]
    fn format_normalizes_variants() {
        assert_eq!(format_trigger_description(&parse_trigger_description("control+t").0, Keysym::t), "ctrl+t");
        assert_eq!(format_trigger_description(&parse_trigger_description("logo+t").0, Keysym::t), "super+t");
    }

    #[test]
    fn to_cosmic_mods_conversion() {
        let smithay_mods = ModifiersState {
            ctrl: true,
            alt: true,
            shift: false,
            logo: true,
            ..Default::default()
        };
        let cosmic_mods = GlobalShortcutsState::to_cosmic_mods(&smithay_mods);
        assert_eq!(cosmic_mods.ctrl, true);
        assert_eq!(cosmic_mods.alt, true);
        assert_eq!(cosmic_mods.shift, false);
        assert_eq!(cosmic_mods.logo, true);
    }

    #[test]
    fn activate_tracks_shortcut() {
        let state = GlobalShortcutsState::new_for_test();
        assert_eq!(state.active_shortcut_count(), 0);

        state.activate("shortcut-1");
        assert_eq!(state.active_shortcut_count(), 1);

        state.activate("shortcut-2");
        assert_eq!(state.active_shortcut_count(), 2);

        // Activating same shortcut again doesn't duplicate
        state.activate("shortcut-1");
        assert_eq!(state.active_shortcut_count(), 2);
    }

    #[test]
    fn deactivate_all_clears_shortcuts() {
        let state = GlobalShortcutsState::new_for_test();
        state.activate("shortcut-1");
        state.activate("shortcut-2");
        assert_eq!(state.active_shortcut_count(), 2);

        state.deactivate_all();
        assert_eq!(state.active_shortcut_count(), 0);

        // Deactivating again is a no-op
        state.deactivate_all();
        assert_eq!(state.active_shortcut_count(), 0);
    }

    #[test]
    fn find_shortcut_in_session() {
        let state = GlobalShortcutsState::new_for_test();

        // Add a shortcut to a session
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.0.insert("test-session".to_string(), Default::default());
            let session = sessions.0.get_mut("test-session").unwrap();
            session.shortcuts.insert(
                "my-shortcut".to_string(),
                GlobalShortcut {
                    id: "my-shortcut".to_string(),
                    modifiers: CTRL_ALT,
                    keysym: Keysym::t,
                    description: "Test shortcut".to_string(),
                },
            );
        }

        let mods = ModifiersState {
            ctrl: true,
            alt: true,
            shift: false,
            logo: false,
            ..Default::default()
        };

        assert_eq!(state.find_shortcut(&mods, Keysym::t), Some("my-shortcut".to_string()));
        assert!(state.has_shortcut_grab(&mods, Keysym::t));

        // Wrong key
        assert_eq!(state.find_shortcut(&mods, Keysym::x), None);

        // Wrong modifiers
        let wrong_mods = ModifiersState {
            ctrl: true,
            alt: false,
            ..Default::default()
        };
        assert_eq!(state.find_shortcut(&wrong_mods, Keysym::t), None);
    }
}
