use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use keystore::{
    init_keystore,
    software::{NoEncryptor, SoftwareKeystore},
};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient, LoginClientInfo};
use plist::Dictionary;
use rand::distributions::{Alphanumeric, DistString};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use toml_edit::{value, Document};

use icloud_auth::{AppleAccountCache, LoginStep, SecondFactorMethod};
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

// ── Persistent device profile ───────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeviceProfile {
    name: String,
    serial: String,
    model: String,
    model_class: String,
    device_uuid: String,
    udid: String,
    os_version: String,
    build: String,
    cfnetwork_version: String,
    darwin_version: String,
}

#[derive(Debug)]
struct LoadedDeviceProfile {
    profile: DeviceProfile,
    path: PathBuf,
    document: Document,
    escrow_password: Option<String>,
}

impl DeviceProfile {
    fn load(path: &Path) -> Result<LoadedDeviceProfile, Box<dyn std::error::Error>> {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".template.toml"))
        {
            return Err(format!(
                "{} is a template. Copy it to a private path such as .local/device-profile.toml and use that copy.",
                path.display()
            )
            .into());
        }

        let source = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "Could not read device profile {}: {error}. Copy device-profile.template.toml to a private path and pass it with --device-profile.",
                path.display()
            )
        })?;
        let mut document = source
            .parse::<Document>()
            .map_err(|error| format!("Invalid device profile {}: {error}", path.display()))?;

        let mut generated_identifiers = false;
        let device_uuid = profile_string(&document, "device", "device_uuid")?;
        let device_uuid = if device_uuid.is_empty() {
            generated_identifiers = true;
            let generated = uuid::Uuid::new_v4().to_string().to_uppercase();
            document["device"]["device_uuid"] = value(&generated);
            generated
        } else {
            uuid::Uuid::parse_str(&device_uuid).map_err(|_| "device_uuid must be a valid UUID")?;
            device_uuid
        };

        let udid = profile_string(&document, "device", "udid")?;
        let udid = if udid.is_empty() {
            generated_identifiers = true;
            let generated = format!("{:032X}", rand::random::<u128>());
            document["device"]["udid"] = value(&generated);
            generated
        } else {
            if udid.len() != 32 || !udid.chars().all(|character| character.is_ascii_hexdigit()) {
                return Err("udid must contain exactly 32 hexadecimal characters".into());
            }
            udid
        };

        let profile = Self {
            name: required_profile_string(&document, "device", "name")?,
            serial: required_profile_string(&document, "device", "serial")?,
            model: required_profile_string(&document, "software", "model")?,
            model_class: required_profile_string(&document, "software", "model_class")?,
            device_uuid,
            udid,
            os_version: required_profile_string(&document, "software", "os_version")?,
            build: required_profile_string(&document, "software", "build")?,
            cfnetwork_version: required_profile_string(&document, "software", "cfnetwork_version")?,
            darwin_version: required_profile_string(&document, "software", "darwin_version")?,
        };
        let escrow_password = profile_string(&document, "escrow", "password")?;
        let escrow_password_configured = profile_bool(&document, "escrow", "configured")?;

        if generated_identifiers {
            write_private_file_atomic(path, document.to_string().as_bytes())?;
            eprintln!(
                "Generated and saved persistent device UUID and UDID in {}",
                path.display()
            );
        }
        if escrow_password_configured {
            ensure_private_profile_permissions(path)?;
        }

        Ok(LoadedDeviceProfile {
            profile,
            path: path.to_path_buf(),
            document,
            escrow_password: escrow_password_configured.then_some(escrow_password),
        })
    }
}

impl LoadedDeviceProfile {
    fn save_escrow_password(&mut self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.document["escrow"]["password"] = value(password);
        self.document["escrow"]["configured"] = value(true);
        write_private_file_atomic(&self.path, self.document.to_string().as_bytes())?;
        self.escrow_password = Some(password.to_string());
        Ok(())
    }
}

#[async_trait]
impl OSConfig for DeviceProfile {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    fn get_model_class(&self) -> String {
        self.model_class.clone()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Ok(vec![])
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.model.clone(),
            os_version: format!("iPhone OS,{},{}", self.os_version, self.build),
            software_version: self.build.clone(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!(
            "{item} CFNetwork/{} Darwin/{}",
            self.cfnetwork_version, self.darwin_version
        )
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!(
            "<{}> <iPhone OS;{};{}> <{}>",
            self.model, self.os_version, self.build, for_item
        )
    }

    fn get_version_ua(&self) -> String {
        format!(
            "[iPhone OS,{},{},{}]",
            self.os_version, self.build, self.model
        )
    }

    fn get_device_name(&self) -> String {
        self.name.clone()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.os_version.clone(),
            hardware_version: self.model.clone(),
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

fn profile_string(
    document: &Document,
    section: &str,
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    document
        .get(section)
        .and_then(|item| item.get(key))
        .and_then(|item| item.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("device profile field `{section}.{key}` must be a string").into())
}

fn required_profile_string(
    document: &Document,
    section: &str,
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let result = profile_string(document, section, key)?;
    if result.is_empty() {
        Err(format!("device profile field `{section}.{key}` cannot be empty").into())
    } else {
        Ok(result)
    }
}

fn profile_bool(
    document: &Document,
    section: &str,
    key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    document
        .get(section)
        .and_then(|item| item.get(key))
        .and_then(|item| item.as_bool())
        .ok_or_else(|| format!("device profile field `{section}.{key}` must be a boolean").into())
}

// ── Serial number extraction ────────────────────────────────────────────

fn serial_from_identifier(identifier: &str) -> Option<String> {
    if !identifier.contains("~#") {
        return None;
    }
    let tail = identifier.rsplit("~#").next()?;
    if tail.starts_with('¶') {
        let sections: Vec<&str> = tail.split('§').collect();
        if sections.len() >= 3 {
            return hex::decode(sections[2])
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok());
        }
        return None;
    }
    Some(tail.to_string())
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
    if let Some(ref gid) = acc.master_record.group_identifier {
        dict.insert(
            "groupIdentifier".to_string(),
            plist::Value::String(gid.clone()),
        );
    }
    plist::Value::Dictionary(dict)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn accessory_to_json(acc: &BeaconAccessory) -> serde_json::Value {
    let secondary = acc
        .master_record
        .shared_secret_2
        .as_ref()
        .or(acc.master_record.secure_locations_shared_secret.as_ref());

    let paired_at = acc
        .master_record
        .pairing_date
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| {
            let dt: chrono::DateTime<chrono::Utc> = std::time::SystemTime::UNIX_EPOCH.into();
            dt.to_rfc3339()
        });

    let alignment_date = acc
        .alignment
        .last_index_observation_date
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        });

    // The Apple plist stores the private key as a 32-byte blob, but only the
    // last 28 bytes are the actual SECP224R1 key material.  Truncating to 28
    // bytes matches what FindMy.py expects (see
    // findmy/accessory.py:423 and _AccessoryKeyGenerator which validates
    // len(master_key) == 28).
    let key = acc.master_record.private_key.as_slice();
    let start = key.len().saturating_sub(28);
    let master_key = bytes_to_hex(&key[start..]);

    serde_json::json!({
        "type": "accessory",
        "master_key": master_key,
        "skn": bytes_to_hex(&acc.master_record.shared_secret),
        "sks": secondary.map(|s| bytes_to_hex(s)),
        "paired_at": paired_at,
        "name": acc.naming.name.clone(),
        "model": acc.master_record.model.clone(),
        "identifier": acc.master_record.stable_identifier.clone(),
        "group_identifier": acc.master_record.group_identifier.clone(),
        "serial_number": serial_from_identifier(&acc.master_record.stable_identifier),
        "alignment_date": alignment_date,
        "alignment_index": acc.alignment.last_index_observed,
    })
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

fn accessory_basename(name: &str, model: &str, stable_identifier: &str) -> String {
    let safe_name = sanitize_filename_component(name, "Unknown");
    let safe_model = sanitize_filename_component(model, "unknown-model");
    let safe_identifier = sanitize_filename_component(stable_identifier, "unknown-id");
    format!("{safe_name}_{safe_model}_{safe_identifier}")
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

fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
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

    let mut file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(contents)?;
    file.sync_all()
}

fn write_private_file_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("device-profile.toml");
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temporary_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary_path, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(unix)]
fn ensure_private_profile_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "Device profile {} contains the escrow password and must not be accessible by group or other users; run chmod 600 '{}'",
            path.display(),
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_profile_permissions(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn confirm_empty_escrow_password() -> Result<bool, Box<dyn std::error::Error>> {
    eprint!("The password is empty and provides no protection. Use it anyway? [y/N]: ");
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    Ok(matches!(
        confirmation.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn configure_escrow_password(
    profile: &mut LoadedDeviceProfile,
) -> Result<String, Box<dyn std::error::Error>> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "No escrow password exists in {} and interactive setup is unavailable",
            profile.path.display()
        )
        .into());
    }

    eprintln!();
    eprintln!("No escrow password exists for this device profile.");
    eprintln!("  [1] Generate a random password");
    eprintln!("  [2] Enter my own password");
    eprint!("Choice [1]: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    let password = match input.trim() {
        "" | "1" => Alphanumeric.sample_string(&mut rand::thread_rng(), 16),
        "2" => loop {
            eprint!("Escrow password: ");
            let password = read_password();
            eprint!("Confirm escrow password: ");
            let confirmation = read_password();
            if password != confirmation {
                eprintln!("Passwords do not match. Try again.");
                continue;
            }
            if password.is_empty() && !confirm_empty_escrow_password()? {
                continue;
            }
            break password;
        },
        choice => return Err(format!("Invalid escrow password choice: {choice}").into()),
    };

    profile.save_escrow_password(&password)?;
    eprintln!("Saved escrow password in {}", profile.path.display());
    Ok(password)
}

fn load_or_configure_escrow_password(
    profile: &mut LoadedDeviceProfile,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(password) = std::env::var("EXPORT_FINDMY_ESCROW_PASSWORD") {
        return Ok(password);
    }

    if let Some(password) = &profile.escrow_password {
        Ok(password.clone())
    } else {
        configure_escrow_password(profile)
    }
}

fn load_existing_escrow_password(
    profile: &LoadedDeviceProfile,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Ok(password) = std::env::var("EXPORT_FINDMY_ESCROW_PASSWORD") {
        return Ok(Some(password));
    }

    Ok(profile.escrow_password.clone())
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

fn load_keychain_state<F>(path: &Path, dsid: &str, fresh_state: F) -> (KeychainClientState, bool)
where
    F: Fn() -> KeychainClientState,
{
    if path.exists() {
        let loaded: Result<KeychainClientState, _> = plist::from_file(path);
        match loaded {
            Ok(state) if state.dsid == dsid => {
                eprintln!(
                    "  Loaded keychain trusted-peer state from {}",
                    path.display()
                );
                (state, true)
            }
            Ok(_) => {
                eprintln!("  Ignoring keychain state for a different Apple account");
                (fresh_state(), false)
            }
            Err(error) => {
                eprintln!("  Ignoring unreadable keychain state: {error}");
                (fresh_state(), false)
            }
        }
    } else {
        (fresh_state(), false)
    }
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

    let (mut account, step) =
        AppleAccount::login_step_start(appleid_closure, login_info, anisette_client).await?;

    let mut current_step = step;
    loop {
        match current_step {
            LoginStep::Complete => return Ok(account),
            LoginStep::ChooseSecondFactor(methods) => {
                for (i, method) in methods.iter().enumerate() {
                    match method {
                        SecondFactorMethod::TrustedDevice => {
                            eprintln!("  {i} - Trusted Device");
                        }
                        SecondFactorMethod::Sms { display_number, .. } => {
                            eprintln!("  {i} - SMS ({display_number})");
                        }
                    }
                }
                eprint!("Method [0]: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let index = input.trim().parse::<usize>().unwrap_or(0);
                let method = methods
                    .get(index)
                    .ok_or_else(|| {
                        icloud_auth::Error::AuthSrpWithMessage(
                            0,
                            format!(
                                "Invalid method index {index}. Must be 0-{}.",
                                methods.len() - 1
                            ),
                        )
                    })?;
                current_step = account.login_choose_method(method).await?;
            }
            LoginStep::EnterCode(_pending) => {
                eprint!("Code: ");
                let mut code = String::new();
                std::io::stdin().read_line(&mut code).unwrap();
                let code = code.trim().to_string();
                current_step = account.login_submit_code(_pending, code).await?;
            }
        }
    }
}

async fn delete_escrow_bottle_interactive(
    keychain: &KeychainClient<RemoteAnisetteProviderV3>,
    verify_bottle_password: bool,
    saved_escrow_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bottles = keychain.get_viable_bottles().await?;
    if bottles.is_empty() {
        eprintln!("No usable escrow bottles found.");
        return Ok(());
    }

    eprintln!("Found {} escrow bottle(s):", bottles.len());
    for (i, (_, metadata)) in bottles.iter().enumerate() {
        eprintln!("  [{}] {}", i, escrow_device_description(metadata));
        eprintln!(
            "      serial: {}, build: {}, escrowed: {}",
            metadata.serial, metadata.build, metadata.timestamp
        );
    }

    eprintln!();
    eprintln!("WARNING: This list may include bottles belonging to real Apple devices.");
    eprint!("Choose a bottle to delete, or press Enter to cancel: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let selection = input.trim().to_string();
    if selection.is_empty() {
        eprintln!("Deletion cancelled.");
        return Ok(());
    }

    let index = selection
        .parse::<usize>()
        .map_err(|_| format!("Invalid bottle index: {selection}"))?;
    let (bottle, metadata) = bottles.get(index).ok_or_else(|| {
        format!(
            "Invalid bottle index {index}. Must be 0-{}.",
            bottles.len() - 1
        )
    })?;

    eprintln!(
        "Selected: {} (serial {})",
        escrow_device_description(metadata),
        metadata.serial
    );
    if verify_bottle_password {
        let bottle_password = if let Some(saved_password) = saved_escrow_password {
            eprint!("Escrow password [press Enter to use the saved profile password]: ");
            let entered_password = read_password();
            if entered_password.is_empty() {
                saved_password.to_string()
            } else {
                entered_password
            }
        } else {
            eprint!("Enter the passcode/password for this escrow bottle: ");
            read_password()
        };
        if let Err(error) = keychain
            .recover_bottle(bottle, bottle_password.as_bytes())
            .await
        {
            return Err(format!("Could not unlock the selected escrow bottle: {error}").into());
        }
        eprintln!("Escrow bottle unlocked successfully.");
    } else {
        eprintln!("WARNING: Bottle password verification has been explicitly bypassed.");
    }

    eprint!("Type DELETE {index} to permanently delete this escrow bottle: ");
    input.clear();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != format!("DELETE {index}") {
        eprintln!("Deletion cancelled.");
        return Ok(());
    }

    eprint!(
        "Final confirmation: type the device serial {}: ",
        metadata.serial
    );
    input.clear();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != metadata.serial {
        eprintln!("Deletion cancelled.");
        return Ok(());
    }

    keychain.delete(bottle.id()).await?;
    eprintln!(
        "Deleted escrow bottle: {}",
        escrow_device_description(metadata)
    );
    Ok(())
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    let mut apple_id = String::new();
    let mut anisette_url = "https://ani.sidestore.io".to_string();
    let mut device_profile_path = PathBuf::from(".local/device-profile.toml");
    let mut output_dir = None;
    let mut auth_cache_path = None;
    let mut use_auth_cache = true;
    let mut clear_auth_cache = false;
    let mut keychain_state_path = None;
    let mut clear_keychain_state = false;
    let mut delete_own_escrow_bottle = false;
    let mut skip_escrow_bottle_password = false;

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
            "--device-profile" => {
                i += 1;
                device_profile_path = PathBuf::from(&args[i]);
            }
            "--output-dir" => {
                i += 1;
                output_dir = Some(PathBuf::from(&args[i]));
            }
            "--auth-cache" => {
                i += 1;
                auth_cache_path = Some(PathBuf::from(&args[i]));
            }
            "--no-auth-cache" => {
                use_auth_cache = false;
            }
            "--clear-auth-cache" => {
                clear_auth_cache = true;
            }
            "--keychain-state" => {
                i += 1;
                keychain_state_path = Some(PathBuf::from(&args[i]));
            }
            "--clear-keychain-state" => {
                clear_keychain_state = true;
            }
            "--delete-own-escrow-bottle" => {
                delete_own_escrow_bottle = true;
            }
            "--delete-own-escrow-bottle-without-password" => {
                delete_own_escrow_bottle = true;
                skip_escrow_bottle_password = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: export_findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!("  --anisette-url <url>     Anisette server URL (default: https://ani.sidestore.io)");
                eprintln!(
                    "  --device-profile <path> Private device profile (default: .local/device-profile.toml)"
                );
                eprintln!(
                    "  --output-dir <dir>       Output directory (default: <profile-dir>/keys)"
                );
                eprintln!(
                    "  --auth-cache <path>     Authentication cache (default: <profile-dir>/auth_cache.plist)"
                );
                eprintln!("  --no-auth-cache         Do not read or write the auth cache");
                eprintln!("  --clear-auth-cache      Delete the cache before logging in");
                eprintln!(
                    "  --keychain-state <path> Trusted-peer state (default: <profile-dir>/keychain_state.plist)"
                );
                eprintln!("  --clear-keychain-state  Delete trusted-peer state before joining");
                eprintln!(
                    "  --delete-own-escrow-bottle  Interactively delete an escrow bottle and exit"
                );
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

    let profile_dir = device_profile_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let output_dir = output_dir.unwrap_or_else(|| profile_dir.join("keys"));
    let auth_cache_path = auth_cache_path.unwrap_or_else(|| profile_dir.join("auth_cache.plist"));
    let keychain_state_path =
        keychain_state_path.unwrap_or_else(|| profile_dir.join("keychain_state.plist"));
    let keystore_path = profile_dir.join("keystore.plist");
    let anisette_config_path = profile_dir.join("anisette_state");

    eprintln!("Using device profile: {}", device_profile_path.display());
    let mut loaded_device_profile = DeviceProfile::load(&device_profile_path)?;

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    let keystore_update_path = keystore_path.clone();
    init_keystore(SoftwareKeystore {
        state: plist::from_file(&keystore_path).unwrap_or_default(),
        update_state: Box::new(move |state| {
            let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                let mut serialized = Vec::new();
                plist::to_writer_xml(&mut serialized, state)?;
                write_private_file(&keystore_update_path, &serialized)?;
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!(
                    "Warning: failed to save keystore state to {}: {error}",
                    keystore_update_path.display()
                );
            }
        }),
        encryptor: NoEncryptor,
    });

    if !delete_own_escrow_bottle {
        std::fs::create_dir_all(&output_dir)?;
    }

    if clear_auth_cache && remove_auth_cache(&auth_cache_path)? {
        eprintln!("Removed auth cache: {}", auth_cache_path.display());
    }
    if clear_keychain_state && remove_auth_cache(&keychain_state_path)? {
        eprintln!(
            "Removed keychain trusted-peer state: {}",
            keychain_state_path.display()
        );
    }

    let config: Arc<dyn OSConfig> = Arc::new(loaded_device_profile.profile.clone());
    let total_steps = if delete_own_escrow_bottle { 3 } else { 7 };

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/{total_steps}] Connecting to anisette server...");
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
    eprintln!("[2/{total_steps}] Authenticating Apple ID...");
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

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap().to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    eprintln!("  Logged in (dsid={})", dsid);

    if delete_own_escrow_bottle {
        if use_auth_cache {
            save_auth_cache(&auth_cache_path, &account)?;
            eprintln!(
                "  Saved authentication cache to {}",
                auth_cache_path.display()
            );
        }

        eprintln!("[3/3] Setting up escrow maintenance...");
        let fresh_keychain_state = || {
            eprintln!("  Using default escrow proxy host");
            KeychainClientState::new_with_host(
                dsid.clone(),
                adsid.clone(),
                "https://p97-escrowproxy.icloud.com:443".to_string(),
            )
        };
        let (keychain_state, _) =
            load_keychain_state(&keychain_state_path, &dsid, fresh_keychain_state);

        let account_arc = Arc::new(DebugMutex::new(account));
        let token_provider = TokenProvider::new(account_arc, config.clone());
        let cloudkit = Arc::new(CloudKitClient {
            state: DebugRwLock::new(
                CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState"),
            ),
            anisette: anisette_client.clone(),
            config: config.clone(),
            token_provider: token_provider.clone(),
        });
        let keychain_state_update_path = keychain_state_path.clone();
        let keychain = KeychainClient {
            anisette: anisette_client.clone(),
            token_provider,
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
            client: cloudkit,
        };

        let saved_escrow_password = if skip_escrow_bottle_password {
            None
        } else {
            load_existing_escrow_password(&loaded_device_profile)?
        };
        delete_escrow_bottle_interactive(
            &keychain,
            !skip_escrow_bottle_password,
            saved_escrow_password.as_deref(),
        )
        .await?;
        return Ok(());
    }

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
    let (keychain_state, restored_keychain_state) =
        load_keychain_state(&keychain_state_path, &dsid, fresh_keychain_state);

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
        let escrow_password = load_or_configure_escrow_password(&mut loaded_device_profile)?;

        keychain
            .join_clique_from_escrow(bottle, passcode.as_bytes(), escrow_password.as_bytes())
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

    // ── Step 7: Write plist and json files ──────────────────────────
    eprintln!("[7/7] Writing plist and json files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    let mut output_paths = HashSet::new();

    for acc in accessories.values() {
        let basename = accessory_basename(
            &acc.naming.name,
            &acc.master_record.model,
            &acc.master_record.stable_identifier,
        );
        let plist_path = output_dir.join(format!("{basename}.plist"));
        let json_path = output_dir.join(format!("{basename}.json"));

        for path in [&plist_path, &json_path] {
            if !output_paths.insert(path.clone()) {
                return Err(format!(
                    "multiple accessories resolve to the same output path: {}",
                    path.display()
                )
                .into());
            }
        }

        plist::to_file_xml(&plist_path, &accessory_to_plist(acc))?;
        std::fs::write(
            &json_path,
            serde_json::to_string_pretty(&accessory_to_json(acc))? + "\n",
        )?;

        eprintln!(
            "  {} {} ({}) -> {} + {}",
            acc.naming.emoji,
            acc.naming.name,
            acc.master_record.model,
            plist_path.display(),
            json_path.display()
        );
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory file pair(s) (plist + json) to {}",
        accessories.len(),
        output_dir.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        accessory_basename, accessory_to_json, remove_auth_cache,
        sanitize_filename_component, serial_from_identifier, DeviceProfile,
    };
    use std::fs;

    #[test]
    fn duplicate_names_use_distinct_identifiers() {
        let first = accessory_basename("Keys", "AirTag", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
        let second = accessory_basename("Keys", "AirTag", "11111111-2222-3333-4444-555555555555");

        assert_ne!(first, second);
        assert_eq!(
            first,
            "Keys_AirTag_AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        );
    }

    #[test]
    fn filename_components_replace_unsafe_characters() {
        assert_eq!(
            accessory_basename(
                "Work / Bag",
                "AirPods Pro (3rd generation)",
                "id:with/slashes"
            ),
            "Work___Bag_AirPods_Pro__3rd_generation__id_with_slashes"
        );
    }

    #[test]
    fn empty_components_get_readable_fallbacks() {
        assert_eq!(sanitize_filename_component("", "fallback"), "fallback");
        assert_eq!(
            accessory_basename("", "", ""),
            "Unknown_unknown-model_unknown-id"
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

    #[test]
    fn device_profile_generates_and_persists_stable_identifiers() {
        let directory = std::env::temp_dir().join(format!(
            "export-findmy-device-profile-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("device-profile.toml");
        fs::write(
            &path,
            r#"
[device]
name = "FindMy Export"
serial = "F2LZN0FAKE00"
device_uuid = ""
udid = ""

[software]
model = "iPhone15,2"
model_class = "iMac"
os_version = "17.4"
build = "21E219"
cfnetwork_version = "1494.0.7"
darwin_version = "23.4.0"

[escrow]
password = ""
configured = false
"#,
        )
        .unwrap();

        let first = DeviceProfile::load(&path).unwrap();
        let second = DeviceProfile::load(&path).unwrap();

        assert_eq!(first.profile, second.profile);
        assert_eq!(first.profile.model_class, "iMac");
        assert_eq!(first.profile.udid.len(), 32);
        assert!(first
            .profile
            .udid
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
        assert_eq!(first.escrow_password, None);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn device_profile_persists_even_an_empty_escrow_password() {
        let directory = std::env::temp_dir().join(format!(
            "export-findmy-device-profile-password-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("device-profile.toml");
        fs::write(
            &path,
            r#"
[device]
name = "FindMy Export"
serial = "F2LZN0FAKE00"
device_uuid = "9240D5F0-5A1D-44D7-95CE-CA9D0ED90E9A"
udid = "0123456789ABCDEF0123456789ABCDEF"

[software]
model = "iPhone15,2"
model_class = "iMac"
os_version = "17.4"
build = "21E219"
cfnetwork_version = "1494.0.7"
darwin_version = "23.4.0"

[escrow]
password = ""
configured = false
"#,
        )
        .unwrap();

        let mut profile = DeviceProfile::load(&path).unwrap();
        profile.save_escrow_password("").unwrap();
        let reloaded = DeviceProfile::load(&path).unwrap();

        assert_eq!(reloaded.escrow_password, Some(String::new()));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn device_profile_template_cannot_be_used_directly() {
        let path = std::env::temp_dir().join("device-profile.template.toml");
        let error = DeviceProfile::load(&path).unwrap_err().to_string();

        assert!(error.contains("is a template"));
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "export-findmy-private-file-test-{}",
            uuid::Uuid::new_v4()
        ));
        super::write_private_file(&path, b"secret").unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn serial_from_airtag_identifier() {
        assert_eq!(
            serial_from_identifier("2006~#HWID123~#ABC123"),
            Some("ABC123".to_string())
        );
    }

    #[test]
    fn serial_from_airpods_identifier() {
        assert_eq!(
            serial_from_identifier("a:/uuid-here~#¶model§hwid§485830304141§left"),
            Some("HX00AA".to_string())
        );
    }

    #[test]
    fn serial_from_third_party_identifier() {
        assert_eq!(
            serial_from_identifier("a:/some-uuid~#THIRDPARTY01"),
            Some("THIRDPARTY01".to_string())
        );
    }

    #[test]
    fn serial_from_identifier_without_tilde_hash() {
        assert_eq!(serial_from_identifier("just-an-identifier"), None);
    }

    #[test]
    fn accessory_basename_produces_expected_format() {
        let basename = accessory_basename("Keys", "AirTag", "ID-123");
        assert_eq!(basename, "Keys_AirTag_ID-123");
    }

    #[test]
    fn json_output_has_expected_schema() {
        use rustpush::findmy::{BeaconAccessory, BeaconNamingRecord, BeaconRatchet, KeyAlignmentRecord, MasterBeaconRecord};
        use std::time::SystemTime;

        let master = MasterBeaconRecord {
            product_id: 1,
            stable_identifier: "2006~#HWID~#ABC123".to_string(),
            pairing_date: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000)),
            battery_level: 100,
            shared_secret_2: Some(vec![0xAB, 0xCD]),
            secure_locations_shared_secret: None,
            private_key: vec![0u8; 28],
            system_version: "17.0".to_string(),
            shared_secret: vec![0xEF, 0x01],
            public_key: vec![0x02, 0x03],
            model: "AirTag".to_string(),
            vendor_id: 1,
            is_zeus: 0,
            group_identifier: None,
        };

        let naming = BeaconNamingRecord {
            emoji: "🔑".to_string(),
            name: "Keys".to_string(),
            associated_beacon: "beacon-id".to_string(),
            role_id: 0,
        };

        let alignment = KeyAlignmentRecord {
            beacon_identifier: "beacon-id".to_string(),
            last_index_observed: 42,
            last_index_observation_date: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700003600)),
        };

        let acc = BeaconAccessory {
            master_record: master,
            naming,
            naming_id: "naming-id".to_string(),
            naming_prot_tag: None,
            alignment: alignment.clone(),
            alignment_id: "alignment-id".to_string(),
            aligment_prot_tag: None,
            local_alignment: alignment,
            last_report: None,
            primary_ratchet: BeaconRatchet::default(),
            secondary_ratchet: BeaconRatchet::default(),
        };

        let json = accessory_to_json(&acc);
        let obj = json.as_object().unwrap();

        assert_eq!(obj.get("type").unwrap().as_str().unwrap(), "accessory");
        assert_eq!(obj.get("master_key").unwrap().as_str().unwrap(), "00000000000000000000000000000000000000000000000000000000");
        assert_eq!(obj.get("skn").unwrap().as_str().unwrap(), "ef01");
        assert_eq!(obj.get("sks").unwrap().as_str().unwrap(), "abcd");
        assert_eq!(obj.get("name").unwrap().as_str().unwrap(), "Keys");
        assert_eq!(obj.get("model").unwrap().as_str().unwrap(), "AirTag");
        assert_eq!(obj.get("identifier").unwrap().as_str().unwrap(), "2006~#HWID~#ABC123");
        assert_eq!(obj.get("serial_number").unwrap().as_str().unwrap(), "ABC123");
        assert_eq!(obj.get("alignment_index").unwrap().as_i64().unwrap(), 42);
        assert!(obj.get("group_identifier").unwrap().is_null());
        assert!(obj.get("alignment_date").unwrap().is_string());
    }
}
