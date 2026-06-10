use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use keystore::{
    init_keystore,
    software::{NoEncryptor, SoftwareKeystore},
};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient, LoginClientInfo};
use plist::Dictionary;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use icloud_auth::AppleAccountCache;
use rustpush::cloudkit::{
    pcs_keys_for_record, should_reset, CloudKitClient, CloudKitState, FetchRecordChangesOperation,
    NO_ASSETS,
};
use rustpush::cloudkit_proto::CloudKitRecord;
use rustpush::findmy::{
    BeaconAccessory, BeaconNamingRecord, BeaconRatchet, KeyAlignmentRecord, MasterBeaconRecord,
    FIND_MY_SERVICE, SEARCH_PARTY_CONTAINER,
};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    login_apple_delegates, APSState, ActivationInfo, AppleAccount, DebugMutex, DebugRwLock,
    LoginDelegate, OSConfig, PushError, TokenProvider,
};
use rustpush::{DebugMeta, RegisterMeta};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────

struct FakeIOSConfig {
    device_uuid: String,
    serial: String,
    udid: String,
}

impl FakeIOSConfig {
    fn new() -> Self {
        FakeIOSConfig {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: "F2LZN0FAKE00".to_string(),
            udid: format!("{:032X}", rand::random::<u128>()),
        }
    }
}

#[async_trait]
impl OSConfig for FakeIOSConfig {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Ok(vec![])
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: "iPhone15,2".to_string(),
            os_version: "iPhone OS,17.4,21E219".to_string(),
            software_version: "21E219".to_string(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!("{item} CFNetwork/1494.0.7 Darwin/23.4.0")
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<iPhone15,2> <iPhone OS;17.4;21E219> <{}>", for_item)
    }

    fn get_version_ua(&self) -> String {
        "[iPhone OS,17.4,21E219,iPhone15,2]".to_string()
    }

    fn get_device_name(&self) -> String {
        "iPhone".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: "17.4".to_string(),
            hardware_version: "iPhone15,2".to_string(),
            serial_number: self.serial.clone(),
        }
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn get_aoskit_version(&self) -> String {
        "com.apple.AuthKit/1 (com.apple.akd/1.0)".to_string()
    }

    fn get_udid(&self) -> String {
        self.udid.clone()
    }
}

// ── Plist generation ────────────────────────────────────────────────────

fn accessory_to_plist(acc: &BeaconAccessory) -> plist::Value {
    let mut dict = Dictionary::new();

    dict.insert(
        "privateKey".to_string(),
        plist::Value::Data(acc.master_record.private_key.clone()),
    );
    dict.insert(
        "sharedSecret".to_string(),
        plist::Value::Data(acc.master_record.shared_secret.clone()),
    );
    if let Some(ref ss2) = acc.master_record.shared_secret_2 {
        dict.insert(
            "secondarySharedSecret".to_string(),
            plist::Value::Data(ss2.clone()),
        );
    }
    if let Some(ref slss) = acc.master_record.secure_locations_shared_secret {
        dict.insert(
            "secureLocationsSharedSecret".to_string(),
            plist::Value::Data(slss.clone()),
        );
    }
    dict.insert(
        "publicKey".to_string(),
        plist::Value::Data(acc.master_record.public_key.clone()),
    );
    dict.insert(
        "identifier".to_string(),
        plist::Value::String(acc.master_record.stable_identifier.clone()),
    );
    dict.insert(
        "model".to_string(),
        plist::Value::String(acc.master_record.model.clone()),
    );
    if let Some(pairing_date) = acc.master_record.pairing_date {
        dict.insert(
            "pairingDate".to_string(),
            plist::Value::Date(pairing_date.into()),
        );
    }
    dict.insert(
        "name".to_string(),
        plist::Value::String(acc.naming.name.clone()),
    );
    dict.insert(
        "emoji".to_string(),
        plist::Value::String(acc.naming.emoji.clone()),
    );
    plist::Value::Dictionary(dict)
}

fn escrow_client_metadata_string<'a>(metadata: &'a plist::Value, key: &str) -> Option<&'a str> {
    let plist::Value::Dictionary(metadata) = metadata else {
        return None;
    };
    let plist::Value::String(value) = metadata.get(key)? else {
        return None;
    };
    Some(value)
}

fn escrow_device_description(metadata: &rustpush::keychain::EscrowMetadata) -> String {
    let name = escrow_client_metadata_string(&metadata.client_metadata, "device_name");
    let model_class =
        escrow_client_metadata_string(&metadata.client_metadata, "device_model_class");
    let model = escrow_client_metadata_string(&metadata.client_metadata, "device_model");

    let mut details = Vec::new();
    if let Some(model_class) = model_class {
        details.push(model_class);
    }
    if let Some(model) = model {
        details.push(model);
    }

    match (name, details.is_empty()) {
        (Some(name), false) => format!("{name} ({})", details.join(", ")),
        (Some(name), true) => name.to_string(),
        (None, false) => details.join(", "),
        (None, true) => "unknown device".to_string(),
    }
}

fn sanitize_filename_component(value: &str, fallback: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.chars().any(|c| c.is_alphanumeric()) {
        sanitized
    } else {
        fallback.to_string()
    }
}

fn accessory_filename(name: &str, model: &str, stable_identifier: &str) -> String {
    let safe_name = sanitize_filename_component(name, "Unknown");
    let safe_model = sanitize_filename_component(model, "unknown-model");
    let safe_identifier = sanitize_filename_component(stable_identifier, "unknown-id");
    format!("{safe_name}_{safe_model}_{safe_identifier}.plist")
}

// ── Password reading ────────────────────────────────────────────────────

fn read_password() -> String {
    if std::io::stdin().is_terminal() {
        let pass = disable_echo_read();
        eprintln!();
        pass
    } else {
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        pass.trim().to_string()
    }
}

#[cfg(unix)]
fn disable_echo_read() -> String {
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut termios);
        let old = termios;
        termios.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &termios);
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        libc::tcsetattr(fd, libc::TCSANOW, &old);
        pass.trim().to_string()
    }
}

#[cfg(not(unix))]
fn disable_echo_read() -> String {
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap();
    pass.trim().to_string()
}

fn load_auth_cache(path: &PathBuf) -> Result<AppleAccountCache, Box<dyn std::error::Error>> {
    Ok(plist::from_file(path)?)
}

fn remove_auth_cache(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn save_auth_cache(
    path: &PathBuf,
    account: &AppleAccount<RemoteAnisetteProviderV3>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let cache = account.to_cache()?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    plist::to_writer_xml(file, &cache)?;
    Ok(())
}

fn save_keychain_state(
    path: &Path,
    state: &KeychainClientState,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    plist::to_writer_xml(file, state)?;
    Ok(())
}

async fn login_interactive(
    apple_id: &str,
    login_info: LoginClientInfo,
    anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3>,
) -> Result<AppleAccount<RemoteAnisetteProviderV3>, icloud_auth::Error> {
    eprint!("Password: ");
    let password = read_password();
    let apple_id = apple_id.to_string();
    let password_hash: Vec<u8> = Sha256::digest(password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id.clone(), password_hash.clone());
    let tfa_closure = || {
        eprint!("2FA code: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    };

    AppleAccount::login(appleid_closure, tfa_closure, login_info, anisette_client).await
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    let args: Vec<String> = std::env::args().collect();

    let mut apple_id = String::new();
    let mut anisette_url = "https://ani.sidestore.io".to_string();
    let mut output_dir = PathBuf::from(".");
    let mut auth_cache_path = PathBuf::from("auth_cache.plist");
    let mut use_auth_cache = true;
    let mut clear_auth_cache = false;
    let mut keychain_state_path = PathBuf::from("keychain_state.plist");
    let mut clear_keychain_state = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apple-id" => {
                i += 1;
                apple_id = args[i].clone();
            }
            "--anisette-url" => {
                i += 1;
                anisette_url = args[i].clone();
            }
            "--output-dir" => {
                i += 1;
                output_dir = PathBuf::from(&args[i]);
            }
            "--auth-cache" => {
                i += 1;
                auth_cache_path = PathBuf::from(&args[i]);
            }
            "--no-auth-cache" => {
                use_auth_cache = false;
            }
            "--clear-auth-cache" => {
                clear_auth_cache = true;
            }
            "--keychain-state" => {
                i += 1;
                keychain_state_path = PathBuf::from(&args[i]);
            }
            "--clear-keychain-state" => {
                clear_keychain_state = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: export_findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!("  --anisette-url <url>     Anisette server URL (default: https://ani.sidestore.io)");
                eprintln!(
                    "  --output-dir <dir>       Output directory for plist files (default: .)"
                );
                eprintln!(
                    "  --auth-cache <path>     Plaintext auth cache (default: auth_cache.plist)"
                );
                eprintln!("  --no-auth-cache         Do not read or write the auth cache");
                eprintln!("  --clear-auth-cache      Delete the cache before logging in");
                eprintln!(
                    "  --keychain-state <path> Trusted-peer state (default: keychain_state.plist)"
                );
                eprintln!("  --clear-keychain-state  Delete trusted-peer state before joining");
                eprintln!();
                eprintln!("WARNING: Output plist files contain private key material.");
                return Ok(());
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return Ok(());
            }
        }
        i += 1;
    }

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    std::fs::create_dir_all(&output_dir)?;

    if clear_auth_cache && remove_auth_cache(&auth_cache_path)? {
        eprintln!("Removed auth cache: {}", auth_cache_path.display());
    }
    if clear_keychain_state && remove_auth_cache(&keychain_state_path)? {
        eprintln!(
            "Removed keychain trusted-peer state: {}",
            keychain_state_path.display()
        );
    }

    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/7] Connecting to anisette server...");
    let anisette_config_path = PathBuf::from_str("anisette_state").unwrap();
    std::fs::create_dir_all(&anisette_config_path).ok();

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> = Arc::new(Mutex::new(
        AnisetteClient::new(RemoteAnisetteProviderV3::new(
            anisette_url.clone(),
            login_info.clone(),
            anisette_config_path,
        )),
    ));

    // ── Step 2: Restore or login to Apple ───────────────────────────
    eprintln!("[2/7] Authenticating Apple ID...");
    let mut loaded_from_cache = false;
    let mut account = if use_auth_cache && auth_cache_path.exists() {
        match load_auth_cache(&auth_cache_path) {
            Ok(cache) if cache.username.eq_ignore_ascii_case(&apple_id) => {
                match AppleAccount::from_cache(cache, login_info.clone(), anisette_client.clone()) {
                    Ok(account) => {
                        loaded_from_cache = true;
                        eprintln!("  Loaded cached authentication");
                        Some(account)
                    }
                    Err(error) => {
                        eprintln!("  Ignoring invalid auth cache: {error}");
                        None
                    }
                }
            }
            Ok(cache) => {
                eprintln!(
                    "  Ignoring auth cache for a different Apple ID ({})",
                    cache.username
                );
                None
            }
            Err(error) => {
                eprintln!("  Ignoring unreadable auth cache: {error}");
                None
            }
        }
    } else {
        None
    };

    if account.is_none() {
        account =
            Some(login_interactive(&apple_id, login_info.clone(), anisette_client.clone()).await?);
    }
    let mut account = account.unwrap();

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    eprintln!("[3/7] Fetching MobileMe delegate...");
    let delegates =
        match login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::MobileMe])
            .await
        {
            Ok(delegates) => delegates,
            Err(error) if loaded_from_cache => {
                eprintln!("  Cached authentication was rejected: {error}");
                if remove_auth_cache(&auth_cache_path)? {
                    eprintln!("  Removed rejected authentication cache");
                }
                eprintln!("  Falling back to a fresh login...");
                account = login_interactive(&apple_id, login_info, anisette_client.clone()).await?;
                login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::MobileMe])
                    .await?
            }
            Err(error) => return Err(error.into()),
        };
    let mobileme = delegates.mobileme.expect("No MobileMe delegate returned");

    if use_auth_cache {
        save_auth_cache(&auth_cache_path, &account)?;
        eprintln!(
            "  Saved authentication cache to {}",
            auth_cache_path.display()
        );
    }

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap().to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    eprintln!("  Logged in (dsid={})", dsid);

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    eprintln!("[4/7] Setting up CloudKit & Keychain...");

    let fresh_keychain_state = || {
        KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme).unwrap_or_else(|| {
            eprintln!("  (escrowProxyUrl not in MobileMe config, using default)");
            KeychainClientState::new_with_host(
                dsid.clone(),
                adsid.clone(),
                "https://p97-escrowproxy.icloud.com:443".to_string(),
            )
        })
    };
    let mut restored_keychain_state = false;
    let keychain_state = if keychain_state_path.exists() {
        let loaded: Result<KeychainClientState, _> = plist::from_file(&keychain_state_path);
        match loaded {
            Ok(state) if state.dsid == dsid => {
                restored_keychain_state = true;
                eprintln!(
                    "  Loaded keychain trusted-peer state from {}",
                    keychain_state_path.display()
                );
                state
            }
            Ok(_) => {
                eprintln!("  Ignoring keychain state for a different Apple account");
                fresh_keychain_state()
            }
            Err(error) => {
                eprintln!("  Ignoring unreadable keychain state: {error}");
                fresh_keychain_state()
            }
        }
    } else {
        fresh_keychain_state()
    };

    let account_arc = Arc::new(DebugMutex::new(account));
    let token_provider = TokenProvider::new(account_arc.clone(), config.clone());
    token_provider.set_mme_delegate(mobileme).await;

    let cloudkit_state = CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState");
    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(cloudkit_state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });

    let keychain_state_update_path = keychain_state_path.clone();
    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(keychain_state),
        config: config.clone(),
        update_state: Box::new(move |state| {
            if let Err(error) = save_keychain_state(&keychain_state_update_path, state) {
                eprintln!(
                    "Warning: failed to save keychain trusted-peer state to {}: {error}",
                    keychain_state_update_path.display()
                );
            }
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    // ── Step 5: Join iCloud Keychain circle via escrow ────────────
    eprintln!("[5/7] Joining iCloud Keychain trust circle...");
    if restored_keychain_state && keychain.is_in_clique().await {
        eprintln!("  Reusing saved keychain trust identity");
    } else {
        if restored_keychain_state {
            eprintln!("  Saved keychain identity is no longer trusted; joining again");
        }
        let bottles = keychain.get_viable_bottles().await?;
        if bottles.is_empty() {
            return Err(
                "No usable escrow bottles found. Re-run with RUST_LOG=rustpush::icloud::keychain=info \
                 to see whether Apple returned no bottle records or whether their metadata could not be matched. \
                 Confirm iCloud Keychain is enabled on a trusted Apple device and that device has a passcode."
                    .into(),
            );
        }
        eprintln!("  Found {} escrow bottle(s):", bottles.len());
        for (i, (_, meta)) in bottles.iter().enumerate() {
            eprintln!("    [{}] {}", i, escrow_device_description(meta));
            eprintln!(
                "        serial: {}, build: {}, escrowed: {}",
                meta.serial, meta.build, meta.timestamp
            );
        }
        let bottle_idx = if bottles.len() == 1 {
            0
        } else {
            eprint!("  Choose bottle [0]: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let idx = input.trim().parse::<usize>().unwrap_or(0);
            if idx >= bottles.len() {
                return Err(format!(
                    "Invalid bottle index {}. Must be 0-{}.",
                    idx,
                    bottles.len() - 1
                )
                .into());
            }
            idx
        };
        let (bottle, meta) = &bottles[bottle_idx];
        eprintln!(
            "  Using escrow bottle from device: {} (serial {})",
            escrow_device_description(meta),
            meta.serial
        );
        eprint!("  Enter the passcode of that device: ");
        let passcode = read_password();

        keychain
            .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
            .await?;
        let state = keychain.state.read().await;
        save_keychain_state(&keychain_state_path, &*state)?;
        eprintln!("  Joined keychain trust circle!");
    }

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    eprintln!("[6/7] Fetching FindMy accessories from CloudKit...");

    let container = SEARCH_PARTY_CONTAINER.init(cloudkit.clone()).await?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result = FetchRecordChangesOperation::do_sync(
        &container,
        &[(beacon_zone.clone(), None)],
        &NO_ASSETS,
    )
    .await;
    if should_reset(result.as_ref().err()) {
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    let (_, changes, _) = result?.remove(0);

    for change in changes {
        let identifier = change
            .identifier
            .as_ref()
            .unwrap()
            .value
            .as_ref()
            .unwrap()
            .name()
            .to_string();
        let Some(record) = change.record else {
            continue;
        };
        let record_type = record.r#type.as_ref().unwrap().name().to_string();

        if record_type == MasterBeaconRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item = MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item = BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            naming_records.insert(item.associated_beacon.clone(), (identifier, item));
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item = KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(item.beacon_identifier.clone(), (identifier, item));
        }
    }

    // ── Assemble accessories ────────────────────────────────────────
    let mut accessories: HashMap<String, BeaconAccessory> = HashMap::new();
    let mut matched_naming_records = 0usize;
    let mut matched_alignment_records = 0usize;
    let mut missing_naming_records = Vec::new();
    let mut missing_alignment_records = Vec::new();

    for (id, master) in beacon_records {
        let stable_id = master.stable_identifier.clone();
        let model = master.model.clone();
        let naming = match naming_records.remove(&id) {
            Some(naming) => {
                matched_naming_records += 1;
                naming
            }
            None => {
                missing_naming_records.push((stable_id.clone(), model.clone()));
                (
                    String::new(),
                    BeaconNamingRecord {
                        emoji: "".to_string(),
                        name: format!("Unknown-{}", &stable_id[..8.min(stable_id.len())]),
                        associated_beacon: id.clone(),
                        role_id: 0,
                    },
                )
            }
        };
        let alignment = match alignment_records.remove(&id) {
            Some((alignment_id, alignment)) => {
                matched_alignment_records += 1;
                (alignment_id, alignment)
            }
            None => {
                missing_alignment_records.push((stable_id.clone(), model));
                Default::default()
            }
        };
        accessories.insert(
            id,
            BeaconAccessory {
                master_record: master,
                naming: naming.1,
                naming_id: naming.0,
                naming_prot_tag: None,
                alignment: alignment.1.clone(),
                alignment_id: alignment.0,
                aligment_prot_tag: None,
                local_alignment: alignment.1,
                last_report: None,
                primary_ratchet: BeaconRatchet::default(),
                secondary_ratchet: BeaconRatchet::default(),
            },
        );
    }

    eprintln!(
        "  Matched names for {}/{} accessories and alignment for {}/{}",
        matched_naming_records,
        accessories.len(),
        matched_alignment_records,
        accessories.len()
    );
    for (stable_id, model) in &missing_naming_records {
        eprintln!("    No naming record: {stable_id} ({model})");
    }
    for (stable_id, model) in &missing_alignment_records {
        eprintln!("    No alignment record: {stable_id} ({model})");
    }
    if !naming_records.is_empty() || !alignment_records.is_empty() {
        eprintln!(
            "  Ignored {} unmatched naming record(s) and {} unmatched alignment record(s)",
            naming_records.len(),
            alignment_records.len()
        );
    }

    // ── Step 7: Write plist files ───────────────────────────────────
    eprintln!("[7/7] Writing plist files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    let mut output_paths = HashSet::new();

    for acc in accessories.values() {
        let filename = accessory_filename(
            &acc.naming.name,
            &acc.master_record.model,
            &acc.master_record.stable_identifier,
        );
        let path = output_dir.join(filename);
        if !output_paths.insert(path.clone()) {
            return Err(format!(
                "multiple accessories resolve to the same output path: {}",
                path.display()
            )
            .into());
        }
        plist::to_file_xml(&path, &accessory_to_plist(acc))?;

        eprintln!(
            "  {} {} ({}) -> {}",
            acc.naming.emoji,
            acc.naming.name,
            acc.master_record.model,
            path.display()
        );
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory plist file(s) to {}",
        accessories.len(),
        output_dir.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{accessory_filename, remove_auth_cache, sanitize_filename_component};
    use std::fs;

    #[test]
    fn duplicate_names_use_distinct_identifiers() {
        let first = accessory_filename("Keys", "AirTag", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
        let second = accessory_filename("Keys", "AirTag", "11111111-2222-3333-4444-555555555555");

        assert_ne!(first, second);
        assert_eq!(
            first,
            "Keys_AirTag_AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE.plist"
        );
    }

    #[test]
    fn filename_components_replace_unsafe_characters() {
        assert_eq!(
            accessory_filename(
                "Work / Bag",
                "AirPods Pro (3rd generation)",
                "id:with/slashes"
            ),
            "Work___Bag_AirPods_Pro__3rd_generation__id_with_slashes.plist"
        );
    }

    #[test]
    fn empty_components_get_readable_fallbacks() {
        assert_eq!(sanitize_filename_component("", "fallback"), "fallback");
        assert_eq!(
            accessory_filename("", "", ""),
            "Unknown_unknown-model_unknown-id.plist"
        );
    }

    #[test]
    fn removing_auth_cache_is_idempotent() {
        let path = std::env::temp_dir().join(format!(
            "export-findmy-auth-cache-test-{}.plist",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, b"rejected cache").unwrap();

        assert!(remove_auth_cache(&path).unwrap());
        assert!(!path.exists());
        assert!(!remove_auth_cache(&path).unwrap());
    }
}
