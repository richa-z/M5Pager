# M5Pager

An off-grid, end-to-end encrypted text pager for the [M5Stack Cardputer](https://docs.m5stack.com/en/core/Cardputer) (StampS3). No SIM, no internet, no server in the middle — two or more Cardputers talk to each other directly over the ESP32's radio using ESP-NOW. Type on the little keyboard, pick a contact, send. Messages are encrypted on your device and only decrypt on the recipient's.

Think of it as a walkie-talkie for text: whoever is in radio range and has your key can reach you.

## What it does

- **Direct device-to-device messaging** over ESP-NOW (no router or account required). If a known network is around it joins it; otherwise it spins up its own AP.
- **End-to-end encryption** with per-message forward secrecy. Each contact gets its own encrypted session; a captured message can't be read by anyone but the two of you.
- **Contacts** — add, edit, and remove people; each contact is tied to their device's public key.
- **Password lock** — the device encrypts its own keys behind a password you set on first boot, and re-locks itself after 5 minutes of inactivity.
- **Encrypted storage** — contacts and config on the SD card are encrypted at rest, not sitting in plaintext JSON.
- **Long messages** are split into chunks and reassembled on the other end; short ACKs tell you when something was delivered.
- **Status bar** with battery level, plus a simple menu-driven UI (Contacts, Settings, change username, Wi-Fi settings, etc.).

## Hardware

- **M5Stack Cardputer** (built around the M5Stack StampS3 / ESP32-S3).
- A **microSD card** — required. Config and contacts live at `/m5pager/` on the card.

You need at least two of them to actually message anyone.

## How the crypto works (short version)

- Every device derives a long-term **X25519** identity key from a private key stored in the ESP32's encrypted NVS. That private key is wrapped with a key derived from your password via **PBKDF2** (200k iterations).
- When you first message a contact, the two devices run an **X25519 handshake** using ephemeral keys to agree on a shared secret — this is what gives you forward secrecy.
- From there, messages are encrypted with **AES-256-GCM** and a **ratcheting** chain key that advances every message, so keys aren't reused. There's a per-message counter and a skipped-message window to handle out-of-order or dropped packets and to reject replays.
- Each session has a short **fingerprint** you can compare out-of-band to check you're not being MITM'd.

If you want the gory details, read the source in `src/security/` — `message_crypto.h` and `device_key_store.h` are heavily commented (in Slovak).

> **Heads up on security:** this is a hobby/experimental project, not an audited secure-messaging product. A self-audit was done, however it might not have found all weaknesses of the project in it's current state. Please think twice before using this to message sensitive information long-term.

## Building & flashing

This is a [PlatformIO](https://platformio.org/) project.

```bash
# with the PlatformIO CLI
pio run                 # build
pio run --target upload # build + flash over USB
pio device monitor      # serial monitor
```

Or just open the folder in VS Code with the PlatformIO extension and hit **Upload**.

The board and framework are set in [`platformio.ini`](platformio.ini):

```ini
[env:m5stack-stamps3]
platform  = espressif32
board     = m5stack-stamps3
framework = arduino
```

**Dependencies:** the project pulls in `M5Cardputer`, `M5Unified`, `ArduinoJson`, and uses the mbedTLS that ships with the ESP32 Arduino core. It's currently wired to pick up libraries from `~/Documents/Arduino/libraries` (see `lib_extra_dirs` in `platformio.ini`) — adjust that path or move the libs into `lib/` if your setup differs.

## First boot

1. Insert a microSD card and power on.
2. The device provisions its identity key and shows a **Key ID** (your public-key fingerprint).
3. You'll be asked to **set a password** — this protects your keys and unlocks the device. There's also a Wi-Fi password prompt for the pager network (`PAGER_COM` by default).
4. After that it drops into the main menu. Set your username under Settings, then add a contact and start messaging.

The device re-locks after 5 minutes idle; you re-enter your password to get back in.

## Using it

- **Navigation:** `;` = up, `.` = down, **Enter** = select, **Backspace** = back. Regular keys type text.
- **Add a contact:** Contacts → add, then run the key exchange with them nearby.
- **Send a message:** pick a contact, type, hit Enter. You'll see a delivery ACK when it lands.

## Project layout

```
src/
  m5pager.ino            # setup(), loop(), ESP-NOW send/receive, message assembly, lock/unlock
  types.h                # packet format, (de)serialization, message reassembly structs
  menus.h / menus/       # menu state machine + one file per screen
  gui_handlers.h         # drawing helpers, status bar, theming
  json_management.h      # encrypted config/contacts load & save
  enums/                 # packet types, contact-add types
  security/
    device_key_store.h   # identity key, password wrapping (PBKDF2), NVS storage, filesystem key
    message_crypto.h     # X25519 handshake, ratchet, AES-256-GCM encrypt/decrypt, fingerprints
  util/                  # network + text-input + misc helpers
AUDIT.md                 # self-security-audit with known issues
platformio.ini
```

## SD card contents

Created automatically on first run, under `/m5pager/`:

- `config.json` — username, Wi-Fi SSID/password (encrypted at rest)
- `contacts.json` — your contacts and their session state (encrypted at rest)

## Status & caveats

This is a personal/experimental project. It works, but treat it accordingly:

- Range and reliability depend on ESP-NOW radio conditions.
- Code comments are mostly in **Slovak**.

## License

No license file is included yet -> all rights reserved by default until one is added. If you want to reuse this, ask first.
