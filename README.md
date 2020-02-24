# ares
![Test](https://github.com/ivan770/ares/workflows/Test/badge.svg)

CLI-based encryption tool, written in Rust
## Algorithm
ares is using AES-128-CBC.

It's file format is simple - IV at file start, ciphertext at the end.
## Download
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/ares)

To download latest stable release, check [releases page](https://github.com/ivan770/ares/releases).

You can also download [unstable releases](https://github.com/ivan770/ares/actions), built by GitHub Actions

## Usage
`ares help` - Show help message with available commands, and ares version

`ares encrypt FROM TO` - Encrypt file on path FROM, and save encrypted result to file TO

`ares decrypt FROM TO` - Decrypt file on path FROM, and save decrypted result to file TO

While using `encrypt` and `decrypt` commands, encryption key will be requested at runtime, and it's input is hidden.

**Make sure that your encryption key is exactly 16 characters long**
