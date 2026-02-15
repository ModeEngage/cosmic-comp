# `cosmic-comp`

## Building

Using Pop!OS 24.04:

1. Install [nix](https://nixos.org/download/)
1. Install the appropriate dev libraries:
    ```sh
    sudo apt install \
        libudev-dev \
        libseat-dev \
        libdisplay-info-dev \
        libinput-dev \
        libpixman-1-dev \
        libxkbcommon-dev \
        libgbm-dev
    ```
1. Launch the appropriate shell using nix:
    ```
    nix shell github:oxalica/rust-overlay --extra-experimental-features nix-command --extra-experimental-features flakes
    ```
1. Use `make`, `cargo` et al from the nix shell.
