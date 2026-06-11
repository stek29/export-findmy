# export-findmy

Export AirTag/FindMy accessory private keys from iCloud, producing `.plist` and `.json` files compatible with [FindMy.py](https://github.com/malmeloo/FindMy.py).

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

Create a private local workspace from the committed template, then edit the
copied identity if desired:

```bash
cp device-profile.template.toml .local/device-profile.toml
$EDITOR .local/device-profile.toml
```

The exporter refuses to run directly from a `*.template.toml` file. The
`.local/` directory is ignored by Git. Keep using the same copied profile: its
UUID, UDID, and escrow password are generated or entered on first use and
persisted there. The private profile uses `[device]`, `[software]`, and
`[escrow]` sections and is rewritten atomically with mode `0600` on Unix.
When changing the device preset, keep `model`, `model_class`, `os_version`,
`build`, `cfnetwork_version`, and `darwin_version` consistent with one another.

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --device-profile .local/device-profile.toml
```

The tool will prompt for:
1. **Password** (hidden input)
2. **2FA code** — enter the code shown on a trusted device, or the SMS code if Apple uses SMS verification
3. **Device passcode** — the screen lock passcode (iPhone PIN) or login password (Mac) of the device listed
4. **Escrow password setup** — generate a random 16-character password or
   enter and confirm your own password

After the keys have been exported and you no longer need this exporter to
remain recoverable in iCloud Keychain, delete the escrow bottle it created:

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --device-profile .local/device-profile.toml \
  --delete-own-escrow-bottle
```

Select only the synthetic exporter record identified by the name, serial,
model, and model class in your device profile. Press Enter at the escrow
password prompt to use the password stored in `[escrow]`, or enter a different
password for a bottle created with another profile or password. Verify all
displayed metadata before confirming deletion; other entries can belong to
your real Apple devices.

By default, all generated local data is kept beside the selected profile:

```text
.local/
├── device-profile.toml
├── auth_cache.plist
├── keychain_state.plist
├── keystore.plist
├── anisette_state/
└── keys/
```

The plist and anisette state intentionally remain separate files. They contain
large or frequently updated binary data; embedding them would make every state
change rewrite the identity and password profile and increase corruption risk.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--apple-id <email>` | Apple ID email | prompted if omitted |
| `--anisette-url <url>` | Anisette v3 server URL | `https://ani.sidestore.io` |
| `--device-profile <path>` | Private device identity, escrow password, and local workspace | `.local/device-profile.toml` |
| `--output-dir <dir>` | Where to write plist and json files | `<profile-dir>/keys` |
| `--auth-cache <path>` | Plaintext authentication cache | `<profile-dir>/auth_cache.plist` |
| `--no-auth-cache` | Disable authentication cache reads and writes | off |
| `--clear-auth-cache` | Delete the cache before authenticating | off |
| `--keychain-state <path>` | Trusted-peer/keychain state used to avoid rejoining | `<profile-dir>/keychain_state.plist` |
| `--clear-keychain-state` | Delete trusted-peer state before joining | off |
| `--delete-own-escrow-bottle` | Interactively select and delete an escrow bottle, then exit | off |

The escrow password is loaded in this order:

1. `EXPORT_FINDMY_ESCROW_PASSWORD`
2. `password` under `[escrow]` in the private device profile
3. Interactive first-time setup

Once a password is configured, group- or other-readable private profiles are
rejected on Unix. The environment override is ephemeral and is not written
into the profile.

Escrow bottle deletion is a maintenance operation:

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --device-profile .local/device-profile.toml \
  --delete-own-escrow-bottle
```

The command lists viable bottles and requires successful recovery using the
selected bottle's password, an explicit `DELETE <index>` confirmation, and
exact re-entry of the selected device serial. Press Enter to use the saved
profile password, or type another bottle password. The list can include
bottles belonging to real Apple devices, so verify the device name, model,
serial, build, and escrow timestamp carefully. The command exits after deletion
without joining the keychain or exporting accessories.
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
$ ./target/release/export-findmy --apple-id xxxx@xxx --device-profile .local/device-profile.toml
Using device profile: .local/device-profile.toml
Generated and saved persistent device UUID and UDID in .local/device-profile.toml
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
No escrow password exists for this device profile.
  [1] Generate a random password
  [2] Enter my own password
Choice [1]:
Saved escrow password in .local/device-profile.toml
  Joined keychain trust circle!
[6/7] Fetching FindMy accessories from CloudKit...
[7/7] Writing plist and json files...
  🎧 Wilbur's AirTag (AirTag) -> .local/keys/Wilbur_s_AirTag_01234567-89AB-CDEF-0123-456789ABCDEF.plist + .local/keys/Wilbur_s_AirTag_01234567-89AB-CDEF-0123-456789ABCDEF.json

Done! Exported 1 accessory file pair(s) (plist + json) to .local/keys
```

## Output format

Each accessory produces a matched pair of files with the same basename:

- `.plist` — Apple-style property-list format
- `.json` — FindMy.py native JSON format

### Plist contents

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
| `groupIdentifier` | Group ID for multi-part accessories (e.g. AirPods), if present |

### JSON contents

| Key | Description |
|-----|-------------|
| `type` | Always `"accessory"` |
| `master_key` | Last 28 bytes of the private key (hex) |
| `skn` | Primary shared secret (hex) |
| `sks` | Secondary shared secret (hex) |
| `paired_at` | Pairing timestamp (ISO 8601) |
| `name` | User-assigned name |
| `model` | Hardware model |
| `identifier` | Stable accessory identifier |
| `group_identifier` | Group ID for multi-part accessories (e.g. AirPods) |
| `serial_number` | Parsed hardware serial number, when detectable |
| `alignment_date` | Last known alignment timestamp (ISO 8601) |
| `alignment_index` | Key index at the alignment timestamp |

Both files contain the same private key material and can be used directly with [FindMy.py](https://github.com/malmeloo/FindMy.py) for tracking AirTag locations.

## Security notes

- **Exported accessory files contain private key material.** This includes both
  the output `.plist` and `.json` files. Treat these files like passwords: do
  not commit, publish, or send them to untrusted systems.
- `auth_cache.plist` contains reusable Apple authentication tokens and the
  SHA-256 hash of your password.
- The private `device-profile.toml` contains the persistent synthetic device
  identity and escrow password. That password is not your Apple ID password or
  a physical device passcode. Keep its UUID, UDID, and password stable after
  creating a bottle, and never commit or share the file.
- `keychain_state.plist` contains the local trusted-peer identity and synced
  keychain state.
- `keystore.plist` contains keychain cryptographic keys. Keep it together with
  `keychain_state.plist`; both are required to reuse the trusted identity.
- `anisette_state/` contains persistent device-provisioning state.
- The recommended `.local/` workspace is ignored by Git. Sensitive files
  created by the exporter use mode `0600` on Unix, but you must also protect
  custom paths and backups yourself.
- Your raw Apple ID password and device passcode are never written to disk.
- After a successful export, delete the synthetic exporter escrow bottle with
  `--delete-own-escrow-bottle` once it is no longer needed. Never delete a
  bottle belonging to a real Apple device.
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
6. Writes accessory data to matched plist and json file pairs

Built on [rustpush](https://github.com/OpenBubbles/rustpush) by the OpenBubbles project.
