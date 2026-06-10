# export-findmy

Export AirTag/FindMy accessory private keys from iCloud, producing `.plist` files compatible with [FindMy.py](https://github.com/malmeloo/FindMy.py).

Should works on any platform? --- Tested on MacOS 26

## Prerequisites

- [Rust toolchain](https://rustup.rs/)
- `openssl` CLI (for building — generates dummy FairPlay certs needed by rustpush)
- `protoc` (protobuf compiler) — `brew install protobuf` on macOS

## Build

```bash
git clone https://github.com/stek29/export-findmy.git
cd export-findmy
cargo build --release
```

## Usage

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --output-dir ./keys
```

The tool will prompt for:
1. **Password** (hidden input)
2. **2FA code** — enter the code shown on a trusted device, or the SMS code if Apple uses SMS verification
3. **Device passcode** — the screen lock passcode (iPhone PIN) or login password (Mac) of the device listed

After the keys have been exported and you no longer need this exporter to
remain recoverable in iCloud Keychain, delete the escrow bottle it created:

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --delete-own-escrow-bottle
```

Select only the synthetic exporter record, currently identified by serial
`F2LZN0FAKE00` and model `iPhone15,2`. Its current bottle password is
`findmy-export`. Verify all displayed metadata before confirming deletion;
other entries can belong to your real Apple devices.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--apple-id <email>` | Apple ID email | prompted if omitted |
| `--anisette-url <url>` | Anisette v3 server URL | `https://ani.sidestore.io` |
| `--output-dir <dir>` | Where to write plist files | `.` |
| `--auth-cache <path>` | Plaintext authentication cache | `auth_cache.plist` |
| `--no-auth-cache` | Disable authentication cache reads and writes | off |
| `--clear-auth-cache` | Delete the cache before authenticating | off |
| `--keychain-state <path>` | Trusted-peer/keychain state used to avoid rejoining | `keychain_state.plist` |
| `--clear-keychain-state` | Delete trusted-peer state before joining | off |
| `--delete-own-escrow-bottle` | Interactively select and delete an escrow bottle, then exit | off |

Escrow bottle deletion is a maintenance operation:

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --delete-own-escrow-bottle
```

The command lists viable bottles and requires successful recovery using the
selected bottle's device passcode/password, an explicit `DELETE <index>`
confirmation, and exact re-entry of the selected device serial. The list can
include bottles belonging to real Apple devices, so verify the device name,
model, serial, build, and escrow timestamp carefully. The command exits after
deletion without joining the keychain or exporting accessories.
It also bypasses the MobileMe delegate request because escrow maintenance only
requires the authenticated Apple account and escrow service.

For focused diagnostics without logging every dependency:

```bash
RUST_BACKTRACE=1 \
RUST_LOG=icloud_auth=debug,omnisette=debug,rustpush::icloud::keychain=debug \
./target/debug/export-findmy --anisette-url "https://ani.neoarz.com"
```

### Example

```
$ ./target/release/export-findmy --apple-id xxxx@xxx --output-dir ./keys
Password:
[1/7] Connecting to anisette server...
[2/7] Logging in to Apple ID...
2FA code: 123456
  Logged in (dsid=......)
[3/7] Fetching MobileMe delegate...
[4/7] Setting up CloudKit & Keychain...
[5/7] Joining iCloud Keychain trust circle...
  Found 1 escrow bottle(s):
    [0] Wilbur's iPhone (iPhone, iPhone 14 Pro)
        serial: L2MPKH342P, build: 21E219, escrowed: 2024-03-20 12:34:56
  Using escrow bottle from device: Wilbur's iPhone (iPhone, iPhone 14 Pro) (serial L2MPKH342P)
  Enter the passcode of that device:
  Joined keychain trust circle!
[6/7] Fetching FindMy accessories from CloudKit...
[7/7] Writing plist files...
  🎧 Wilbur's AirTag (AirTag) -> ./keys/Wilbur_s_AirTag_01234567-89AB-CDEF-0123-456789ABCDEF.plist

Done! Exported 1 accessory plist file(s) to ./keys
```

## Output format

Each accessory produces a `.plist` file containing:

| Key | Description |
|-----|-------------|
| `privateKey` | EC private key (for deriving rolling BLE keys) |
| `sharedSecret` | Primary shared secret |
| `secondarySharedSecret` | Secondary shared secret (if present) |
| `publicKey` | EC public key |
| `identifier` | Stable accessory identifier |
| `name` | User-assigned name |
| `emoji` | User-assigned emoji |
| `model` | Hardware model |
| `pairingDate` | When the accessory was paired |

These files can be used directly with [FindMy.py](https://github.com/malmeloo/FindMy.py) for tracking AirTag locations.

## Security notes

- **Exported accessory files contain private key material.** This includes the
  output plist files and any JSON files produced from them. Treat these files
  like passwords: do not commit, publish, or send them to untrusted systems.
- `auth_cache.plist` contains reusable Apple authentication tokens and the
  SHA-256 hash of your password.
- `keychain_state.plist` contains the local trusted-peer identity and synced
  keychain state.
- `keystore.plist` contains keychain cryptographic keys. Keep it together with
  `keychain_state.plist`; both are required to reuse the trusted identity.
- `anisette_state/` contains persistent device-provisioning state.
- These default paths are ignored by Git. The plist cache/state files created
  by the exporter use mode `0600` on Unix, but you must also protect custom
  paths and backups yourself.
- Your raw Apple ID password and device passcode are never written to disk.
- After a successful export, delete the synthetic exporter escrow bottle with
  `--delete-own-escrow-bottle` once it is no longer needed. This is especially
  important while newly created bottles use the fixed `findmy-export`
  password. Never delete a bottle belonging to a real Apple device.
- When finished, securely remove exported plist/JSON files and all cache,
  account, keychain, and anisette state listed above unless you intentionally
  need them for later runs. Removing the state files requires authenticating
  and joining the keychain trust circle again.
- The anisette server only sees OTP header requests from your IP. It never sees your Apple ID, password, or iCloud data.

## How it works

1. Authenticates to Apple via SRP (using remote anisette for device identity tokens)
2. Fetches MobileMe delegate tokens via the iOS `iosbuddy` login endpoint
3. Joins the iCloud Keychain trust circle via escrow recovery (using your device passcode)
4. Fetches encrypted `BeaconStore` records from CloudKit
5. Decrypts records using PCS (Protected CloudStorage) keys from the keychain
6. Writes accessory data to plist files

Built on [rustpush](https://github.com/OpenBubbles/rustpush) by the OpenBubbles project.
