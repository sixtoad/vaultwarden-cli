//! Installation has no provider, enrollment or credential access. A receipt only
//! selects a complete, validated desktop bundle for a terminal launcher.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(test)]
use std::io::Write;
use std::path::{Component, Path, PathBuf};

mod directory;
use directory::Directory;

pub const ABI: u32 = 1;
const RECEIPT: &str = ".vaultwarden-commands.json";
const PREVIOUS: &str = ".vaultwarden-commands.previous.json";
const MAX_JSON: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub path: String,
    pub sha256: String,
    pub executable: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub command_abi: u32,
    pub platform: String,
    pub architecture: String,
    pub app_version: String,
    pub core_version: String,
    pub cli_version: String,
    pub source_revision: String,
    pub source_inputs_sha256: String,
    pub entrypoint: String,
    pub commands: BTreeMap<String, String>,
    pub roles: BTreeMap<String, bool>,
    pub payloads: Vec<Payload>,
    pub links: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    bundle: PathBuf,
    manifest_sha256: String,
    launcher_sha256: String,
    launcher_bundle: PathBuf,
    launcher_manifest_sha256: String,
    architecture: String,
    commands: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub state: String,
    pub detail: String,
    pub app_version: String,
    pub cli_version: String,
    pub bundle: String,
    pub manifest_sha256: String,
    pub commands: BTreeMap<String, String>,
    pub resolved: BTreeMap<String, String>,
    pub roles: BTreeMap<String, bool>,
}
fn fail(message: &str) -> String {
    message.to_owned()
}
pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}
fn manifest_path(root: &Path) -> PathBuf {
    root.join(if platform() == "macos" {
        "Contents/Resources/bundle.json"
    } else {
        "bundle.json"
    })
}
fn regular(path: &Path) -> Result<fs::Metadata, String> {
    let m =
        fs::symlink_metadata(path).map_err(|_| fail("Missing component or command directory"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(fail("Reparse points are not accepted"));
        }
    }
    if m.file_type().is_symlink() {
        return Err(fail(
            "Symbolic links are not accepted for managed components",
        ));
    }
    Ok(m)
}
fn open_read(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| fail("Cannot read installation file"))?;
    if !file
        .metadata()
        .map_err(|_| fail("Cannot inspect open file"))?
        .is_file()
    {
        return Err(fail("Not a regular installation file"));
    }
    Ok(file)
}
fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let m = regular(path)?;
    if !m.is_file() || m.len() > limit {
        return Err(fail("Invalid file type or size"));
    }
    let mut out = Vec::new();
    open_read(path)?
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|_| fail("Cannot read installation file"))?;
    if out.len() as u64 > limit {
        return Err(fail("Installation file too large"));
    }
    Ok(out)
}
fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn file_hash(path: &Path) -> Result<String, String> {
    if !regular(path)?.is_file() {
        return Err(fail("Component is not a regular file"));
    }
    let mut file = open_read(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| fail("Cannot read component"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn safe_child(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty() || relative.contains('\\') {
        return Err(fail("Invalid component path"));
    }
    let p = Path::new(relative);
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(fail("Unsafe component path"));
    }
    let mut current = root.to_path_buf();
    for c in p.components() {
        current.push(c);
        regular(&current)?;
    }
    Ok(current)
}
fn binary_name(name: &str) -> String {
    format!("{name}{}", if cfg!(windows) { ".exe" } else { "" })
}
fn command_path(name: &str) -> String {
    format!(
        "{}{}",
        if platform() == "macos" {
            "Contents/Helpers/"
        } else {
            "commands/"
        },
        binary_name(name)
    )
}
/// Linux, and native macOS on Apple Silicon only: the macOS provider rejects
/// Intel/Rosetta at runtime, so an x86_64 macOS bundle never advertises it.
fn protected_bundle() -> bool {
    platform() == "linux" || (platform() == "macos" && std::env::consts::ARCH == "aarch64")
}
fn expected_commands() -> Vec<String> {
    let mut commands = vec!["vaultwarden-cli".to_owned()];
    if protected_bundle() {
        commands.push("vw-access".to_owned());
    }
    commands
}
/// Bundled provider binaries that are not user commands. The native macOS
/// provider does not use Linux's systemd helper `vaultwarden-access-exec`.
fn expected_provider_components() -> Vec<&'static str> {
    match (platform(), protected_bundle()) {
        ("linux", _) => vec!["vaultwarden-accessd", "vaultwarden-access-exec"],
        ("macos", true) => vec!["vaultwarden-accessd"],
        _ => Vec::new(),
    }
}
fn expected_roles() -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("protected_requesting".into(), protected_bundle()),
        ("desktop_approval".into(), platform() == "macos"),
        ("protected_provider".into(), protected_bundle()),
        ("vault_cli".into(), true),
    ])
}
fn app_version() -> &'static str {
    include_str!("../../pubspec.yaml")
        .lines()
        .find_map(|line| line.strip_prefix("version: "))
        .unwrap_or("")
}
fn verify_signature(root: &Path) -> Result<(), String> {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        let status = std::process::Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(root)
            .output()
            .map_err(|_| fail("Cannot verify application signature"))?;
        if !status.status.success() {
            return Err(fail(
                "Application signature is damaged; obtain a complete verified bundle",
            ));
        }
    }
    #[cfg(any(not(target_os = "macos"), test))]
    let _ = root;
    Ok(())
}
fn validate_contract(root: &Path, running_app: bool) -> Result<(Manifest, String), String> {
    if !root.is_absolute()
        || !regular(root)?.is_dir()
        || root
            .canonicalize()
            .map_err(|_| fail("Cannot resolve bundle"))?
            != root
    {
        return Err(fail(
            "Unsafe bundle root; open the application from its real location",
        ));
    }
    let data = bytes(&manifest_path(root), MAX_JSON)?;
    let envelope: serde_json::Value =
        serde_json::from_slice(&data).map_err(|_| fail("Damaged bundle manifest"))?;
    match envelope.get("schema").and_then(serde_json::Value::as_u64) {
        Some(1) => {}
        Some(_) => {
            return Err(fail(
                "Incompatible bundle schema; update the complete application",
            ))
        }
        None => return Err(fail("Damaged bundle manifest schema")),
    }
    let manifest: Manifest =
        serde_json::from_slice(&data).map_err(|_| fail("Damaged bundle manifest"))?;
    if manifest.schema != 1
        || manifest.command_abi != ABI
        || manifest.platform != platform()
        || manifest.architecture != std::env::consts::ARCH
        || (running_app
            && (manifest.core_version != env!("CARGO_PKG_VERSION")
                || manifest.app_version != app_version()))
    {
        return Err(fail(
            "Incompatible app, core or bundle contract; update the complete bundle",
        ));
    }
    if manifest.entrypoint != "lib/main.dart"
        || manifest.roles != expected_roles()
        || manifest.commands
            != expected_commands()
                .into_iter()
                .map(|n| (n.clone(), command_path(&n)))
                .collect()
        || manifest.cli_version.is_empty()
        || !hex(&manifest.source_inputs_sha256)
        || manifest.source_revision.len() != 40
        || !manifest
            .source_revision
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err(fail("Invalid bundle identity, capabilities or entrypoint"));
    }
    let mut required = manifest.commands.values().cloned().collect::<Vec<_>>();
    required.push(command_path("companion-command"));
    required.extend(expected_provider_components().into_iter().map(command_path));
    required.push(
        match platform() {
            "macos" => "Contents/Frameworks/libcompanion_core.dylib",
            "windows" => "companion_core.dll",
            _ => "lib/libcompanion_core.so",
        }
        .to_owned(),
    );
    required.push(
        match platform() {
            "macos" => "Contents/MacOS/companion_slice",
            "windows" => "companion_slice.exe",
            _ => "companion_slice",
        }
        .to_owned(),
    );
    required.extend(match platform() {
        "linux" => vec![
            "lib/libflutter_linux_gtk.so".into(),
            "lib/libapp.so".into(),
            "data/icudtl.dat".into(),
        ],
        "windows" => vec![
            "flutter_windows.dll".into(),
            "msvcp140.dll".into(),
            "vcruntime140.dll".into(),
            "data/app.so".into(),
            "data/icudtl.dat".into(),
        ],
        _ => vec![
            "Contents/Frameworks/App.framework/Versions/A/App".into(),
            "Contents/Frameworks/FlutterMacOS.framework/Versions/A/FlutterMacOS".into(),
        ],
    });
    for (relative, target) in &manifest.links {
        let path = root.join(relative);
        if Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
            || !fs::symlink_metadata(&path)
                .map_err(|_| fail("Missing framework link"))?
                .file_type()
                .is_symlink()
            || fs::read_link(&path).map_err(|_| fail("Unreadable framework link"))?
                != Path::new(target)
            || !path
                .canonicalize()
                .map_err(|_| fail("Stale framework link"))?
                .starts_with(root)
        {
            return Err(fail("Damaged framework link"));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &manifest.payloads {
        if !seen.insert(entry.path.clone()) {
            return Err(fail("Duplicate bundle component"));
        }
        if (entry.path.starts_with("commands/")
            || entry.path.starts_with("Contents/Helpers/")
            || entry.path == "companion_slice"
            || entry.path == "companion_slice.exe"
            || entry.path == "Contents/MacOS/companion_slice")
            && !entry.executable
        {
            return Err(fail("Invalid executable component record"));
        }
        let path = safe_child(root, &entry.path)?;
        // The Mach-O app signature binds the manifest, so its hash belongs in
        // the external artifact inventory instead (avoids a circular signature).
        let signed_app = platform() == "macos" && entry.path == "Contents/MacOS/companion_slice";
        if !signed_app && (!hex(&entry.sha256) || file_hash(&path)? != entry.sha256) {
            return Err(fail(
                "Damaged bundle component; replace the complete bundle",
            ));
        }
        if signed_app && !entry.sha256.is_empty() {
            return Err(fail("Invalid signed app record"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if entry.executable && regular(&path)?.permissions().mode() & 0o111 == 0 {
                return Err(fail("Component has lost executable permission"));
            }
        }
    }
    if required.iter().any(|p| !seen.contains(p)) {
        return Err(fail("Missing required bundle component record"));
    }
    for link in manifest.links.keys() {
        seen.insert(format!("@link:{link}"));
    }
    let mut actual = std::collections::BTreeSet::new();
    collect_files(root, root, &mut actual)?;
    if actual != seen {
        return Err(fail(
            "Bundle inventory changed; replace the complete bundle",
        ));
    }
    verify_signature(root)?;
    Ok((manifest, hash(&data)))
}
pub fn validate(root: &Path) -> Result<(Manifest, String), String> {
    validate_contract(root, true)
}
fn collect_files(
    root: &Path,
    directory: &Path,
    out: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    for item in fs::read_dir(directory).map_err(|_| fail("Cannot inspect bundle inventory"))? {
        let path = item
            .map_err(|_| fail("Cannot inspect bundle inventory"))?
            .path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| fail("Invalid inventory path"))?
            .to_string_lossy()
            .replace('\\', "/");
        if relative.split('/').any(|s| s == "_CodeSignature") || path == manifest_path(root) {
            continue;
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| fail("Cannot inspect bundle inventory"))?;
        if metadata.file_type().is_symlink() {
            out.insert(format!("@link:{relative}"));
            continue;
        }
        if metadata.is_dir() {
            collect_files(root, &path, out)?;
        } else if metadata.is_file() {
            out.insert(relative);
        } else {
            return Err(fail("Unsupported bundle file type"));
        }
    }
    Ok(())
}
fn parse_receipt(data: &[u8]) -> Result<Receipt, String> {
    let receipt: Receipt = serde_json::from_slice(data).map_err(|_| fail("Damaged command setup. Preserve this folder and enable commands in a new empty user folder, or restore a valid previous setup."))?;
    if receipt.schema != ABI
        || !receipt.bundle.is_absolute()
        || !hex(&receipt.manifest_sha256)
        || !hex(&receipt.launcher_sha256)
        || !receipt.launcher_bundle.is_absolute()
        || !hex(&receipt.launcher_manifest_sha256)
        || receipt.commands != expected_commands()
        || !["x86_64", "aarch64"].contains(&receipt.architecture.as_str())
    {
        return Err(fail(
            "Incompatible command setup; enable a new user folder and preserve this installation",
        ));
    }
    Ok(receipt)
}
fn read_receipt(path: &Path) -> Result<Receipt, String> {
    parse_receipt(&bytes(path, MAX_JSON)?)
}
fn receipt_matches(directory: &Path, root: &Path, manifest_hash: &str) -> bool {
    read_receipt(&directory.join(RECEIPT))
        .is_ok_and(|r| r.bundle == root && r.manifest_sha256 == manifest_hash)
}
pub fn inspect(root: &Path, path_env: &str) -> Inspection {
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let root = canonical.as_path();
    let mut out = Inspection {
        state: "missing".into(),
        detail: "The application bundle is incomplete. Obtain a complete desktop bundle.".into(),
        app_version: app_version().into(),
        cli_version: String::new(),
        bundle: root.to_string_lossy().into(),
        manifest_sha256: String::new(),
        commands: BTreeMap::new(),
        resolved: BTreeMap::new(),
        roles: expected_roles(),
    };
    let (m, digest) = match validate(root) {
        Ok(valid) => valid,
        Err(error) => {
            out.state = if error.starts_with("Incompatible") {
                "incompatible"
            } else if error.starts_with("Missing") {
                "missing"
            } else {
                "damaged"
            }
            .into();
            out.detail = error;
            return out;
        }
    };
    out.cli_version = m.cli_version;
    out.manifest_sha256 = digest.clone();
    out.state = "compatible".into();
    out.detail = "Bundle compatible. Enable commands in a user directory, then add that directory to your terminal PATH if needed. Installation grants no vault access.".into();
    for (name, relative) in m.commands {
        out.commands
            .insert(name.clone(), root.join(relative).to_string_lossy().into());
        let mut found = None;
        let mut uncertain_search = false;
        #[cfg(windows)]
        let names = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|ext| {
                ext.starts_with('.')
                    && ext.len() <= 16
                    && ext[1..].bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .map(|ext| format!("{name}{ext}"))
            .collect::<Vec<_>>();
        #[cfg(not(windows))]
        let names = vec![name.clone()];
        'search: for directory in std::env::split_paths(path_env) {
            if !directory.is_absolute() {
                uncertain_search = true;
                continue;
            }
            for filename in &names {
                let candidate = directory.join(filename);
                if let Ok(metadata) = fs::metadata(&candidate) {
                    if !metadata.is_file() {
                        continue;
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if metadata.permissions().mode() & 0o111 == 0 {
                            continue;
                        }
                    }
                    found = Some((directory, candidate));
                    break 'search;
                }
            }
        }
        if uncertain_search {
            out.state = "conflicting".into();
        }
        if let Some((directory, candidate)) = found {
            let managed = read_receipt(&directory.join(RECEIPT))
                .ok()
                .is_some_and(|r| file_hash(&candidate).is_ok_and(|h| h == r.launcher_sha256));
            if !managed || !receipt_matches(&directory, root, &digest) {
                out.state = "conflicting".into();
            }
            out.resolved
                .insert(name, candidate.to_string_lossy().into());
        }
    }
    if out.state == "conflicting" {
        out.detail = "A terminal command may resolve through an empty/relative PATH entry or to a different, stale or unrelated installation. Nothing was executed. Repair only a directory you previously enabled; remove unrelated PATH conflicts yourself.".into();
    }
    out
}
#[cfg(test)]
fn create_new(path: &Path, data: &[u8], executable: bool) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            fail("Cannot create command file; permissions or an existing file prevent activation")
        })?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|_| fail("Cannot write command file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(if executable {
            0o755
        } else {
            0o600
        }))
        .map_err(|_| fail("Cannot set command permissions"))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}
#[cfg(windows)]
fn replace(source: &Path, target: &Path, overwrite: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        // Same-volume atomic replace; write-through persists the activation.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                if overwrite { 1 | 8 } else { 8 },
            )
        } == 0
        {
            return Err(fail("Activation failed; previous commands remain selected"));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    fs::rename(source, target)
        .map_err(|_| fail("Activation failed; previous commands remain selected"))
}
pub fn enable(root: &Path, directory: &Path) -> Result<String, String> {
    #[cfg(unix)]
    let home = {
        // Reentrant account lookup: FRB calls run on multiple worker threads.
        let mut buffer = vec![0u8; 16384];
        loop {
            let mut record: libc::passwd = unsafe { std::mem::zeroed() };
            let mut result = std::ptr::null_mut();
            let status = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    &mut record,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if status != 0 || result.is_null() || record.pw_dir.is_null() {
                return Err(fail("Cannot determine user home"));
            }
            let value = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) };
            use std::os::unix::ffi::OsStrExt;
            break PathBuf::from(std::ffi::OsStr::from_bytes(value.to_bytes()));
        }
    };
    #[cfg(windows)]
    let home = {
        use std::os::windows::ffi::OsStringExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Security::TOKEN_QUERY;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        #[link(name = "userenv")]
        unsafe extern "system" {
            fn GetUserProfileDirectoryW(
                token: *mut std::ffi::c_void,
                output: *mut u16,
                length: *mut u32,
            ) -> i32;
        }
        let mut raw = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(fail("Cannot determine account profile"));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut length = 0;
        unsafe {
            GetUserProfileDirectoryW(token.as_raw_handle(), std::ptr::null_mut(), &mut length);
        }
        if length == 0 || length > 32768 {
            return Err(fail("Cannot determine account profile"));
        }
        let mut buffer = vec![0u16; length as usize];
        if unsafe {
            GetUserProfileDirectoryW(token.as_raw_handle(), buffer.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(fail("Cannot determine account profile"));
        }
        let end = buffer
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| fail("Invalid account profile path"))?;
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end]))
    };
    enable_in(root, directory, &home)
}
fn enable_in(root: &Path, directory: &Path, home: &Path) -> Result<String, String> {
    let root = root
        .canonicalize()
        .map_err(|_| fail("Application moved or missing"))?;
    let (manifest, manifest_hash) = validate(&root)?;
    let directory = Directory::open(home, directory, &root)?;
    let _lock = directory.lock()?;
    enable_locked(&root, &directory, &manifest, &manifest_hash)
}
fn enable_locked(
    root: &Path,
    directory: &Directory,
    manifest: &Manifest,
    manifest_hash: &str,
) -> Result<String, String> {
    let mut damaged_active = None;
    let active_present = directory.exists(RECEIPT);
    let previous = if active_present {
        let data = directory.read(RECEIPT, MAX_JSON)?;
        match parse_receipt(&data) {
            Ok(receipt) => Some((receipt, data)),
            Err(error) => {
                if !directory.exists(PREVIOUS) {
                    return Err(error);
                }
                let backup = directory.read(PREVIOUS, MAX_JSON)?;
                let receipt = parse_receipt(&backup)?;
                damaged_active = Some(data);
                Some((receipt, backup))
            }
        }
    } else if directory.exists(PREVIOUS) {
        let data = directory.read(PREVIOUS, MAX_JSON)?;
        Some((parse_receipt(&data)?, data))
    } else {
        None
    };
    if previous
        .as_ref()
        .is_some_and(|(r, _)| r.architecture != manifest.architecture)
    {
        return Err(fail("Command launcher architecture differs from this bundle. Enable a new empty user folder; the previous command setup is preserved."));
    }
    let launcher = safe_child(root, &command_path("companion-command"))?;
    let launcher_bytes = bytes(&launcher, 100 * 1024 * 1024)?;
    let current_hash = hash(&launcher_bytes);
    let launcher_hash = previous
        .as_ref()
        .map_or_else(|| current_hash.clone(), |(r, _)| r.launcher_sha256.clone());
    let (launcher_bundle, launcher_manifest_sha256) = if launcher_hash == current_hash {
        (root.to_path_buf(), manifest_hash.to_owned())
    } else {
        let Some((old, _)) = &previous else {
            return Err(fail("Missing launcher provenance"));
        };
        let guidance = || {
            fail("The older command launcher cannot be verified against its original bundle. Preserve this command setup and enable a new empty user folder.")
        };
        let (source, digest) =
            validate_contract(&old.launcher_bundle, false).map_err(|_| guidance())?;
        if digest != old.launcher_manifest_sha256
            || source.architecture != manifest.architecture
            || !source.payloads.iter().any(|p| {
                p.path == command_path("companion-command")
                    && p.sha256 == launcher_hash
                    && p.executable
            })
        {
            return Err(guidance());
        }
        (
            old.launcher_bundle.clone(),
            old.launcher_manifest_sha256.clone(),
        )
    };
    let mut mode_repairs = Vec::new();
    for name in expected_commands() {
        let filename = binary_name(&name);
        if directory.exists(&filename) {
            let data = directory.read(&filename, 100 * 1024 * 1024)?;
            if hash(&data) != launcher_hash {
                return Err(fail(
                    "Conflicting command; unrelated files are never overwritten",
                ));
            }
            if !directory.executable(&filename)? {
                mode_repairs.push((filename, data));
            }
        } else if previous.is_some() && hash(&launcher_bytes) != launcher_hash {
            return Err(fail("Missing older launcher. Enable this bundle in a new empty user directory; previous activation is preserved"));
        }
    }
    let next = Receipt {
        schema: ABI,
        bundle: root.to_path_buf(),
        manifest_sha256: manifest_hash.into(),
        launcher_sha256: launcher_hash,
        launcher_bundle,
        launcher_manifest_sha256,
        architecture: manifest.architecture.clone(),
        commands: expected_commands(),
    };
    let encoded = serde_json::to_vec_pretty(&next).map_err(|_| fail("Cannot encode activation"))?;
    let stage = directory.stage(&encoded, false, false)?;
    let result = (|| {
        directory.still_named()?;
        for name in manifest.commands.keys() {
            let filename = binary_name(name);
            if !directory.exists(&filename) {
                let source = directory.stage(&launcher_bytes, true, false)?;
                directory.publish(&source, &filename)?;
            }
        }
        for (filename, data) in mode_repairs {
            // Replace the directory entry with verified identical bytes. Never
            // chmod an existing inode: it may have unrelated hard links.
            let source = directory.stage(&data, true, false)?;
            directory.replace(&source, &filename)?;
            directory.sync()?;
        }
        if validate(root)?.1 != manifest_hash {
            return Err(fail("Bundle changed during activation"));
        }
        directory.still_named()?;
        if active_present
            && damaged_active.is_none()
            && previous.as_ref().is_some_and(|(old, _)| {
                old.bundle == next.bundle
                    && old.manifest_sha256 == next.manifest_sha256
                    && old.launcher_sha256 == next.launcher_sha256
            })
        {
            directory.remove(&stage)?;
            directory.sync()?;
            return Ok(format!("Commands already enabled in {}. PATH is unchanged; reopen the terminal after adding this directory to your user PATH.", directory.path.display()));
        }
        if let Some(data) = damaged_active {
            // Explicit Repair preserves unexplained bytes; a valid previous
            // setup and every managed launcher were checked before recovery.
            directory.stage(&data, false, true)?;
            directory.sync()?;
        }
        if let Some((_, data)) = previous {
            if directory.exists(PREVIOUS) {
                parse_receipt(&directory.read(PREVIOUS, MAX_JSON)?)?;
            }
            let backup = directory.stage(&data, false, false)?;
            directory.replace(&backup, PREVIOUS)?;
            directory.sync()?;
        }
        directory.replace(&stage, RECEIPT)?;
        if directory.sync_activation().is_err() {
            return Ok("The new command setup is active, but durable storage could not be confirmed. Keep the previous bundle, check your disk and repeat repair before removing anything.".into());
        }
        Ok(format!("Commands enabled in {}. Add this exact directory to your user PATH if absent; reopen your terminal. No credentials, enrollment or system PATH were changed.", directory.path.display()))
    })();
    if result.is_err() {
        let _ = directory.remove(&stage);
    }
    result
}
pub fn launch(
    command: &str,
    executable: &Path,
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<i32, String> {
    if !expected_commands().iter().any(|n| n == command) {
        return Err(fail("Unrecognized managed command"));
    }
    let directory = executable
        .parent()
        .ok_or_else(|| fail("Missing launcher directory"))?;
    let receipt = read_receipt(&directory.join(RECEIPT))?;
    if file_hash(executable)? != receipt.launcher_sha256 {
        return Err(fail("Damaged command launcher"));
    }
    let (manifest, digest) = validate_contract(&receipt.bundle, false)?;
    if digest != receipt.manifest_sha256 {
        return Err(fail("Bundle changed; repair from the application Settings"));
    }
    let relative = manifest
        .commands
        .get(command)
        .ok_or_else(|| fail("Unsupported platform command"))?;
    let target = safe_child(&receipt.bundle, relative)?;
    let mut process = std::process::Command::new(target);
    process.args(arguments);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // The terminal job remains the same PID: Ctrl-C, job control and exit
        // signals reach the real CLI without a supervising launcher process.
        Err(format!(
            "Cannot execute bundled command: {}",
            process.exec()
        ))
    }
    #[cfg(windows)]
    {
        let status = process
            .status()
            .map_err(|_| fail("Cannot launch bundled command"))?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Fixture {
        home: PathBuf,
        root: PathBuf,
        directory: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.home);
        }
    }
    impl Fixture {
        fn new() -> Self {
            static ID: AtomicU64 = AtomicU64::new(0);
            let home = std::env::temp_dir().join(format!(
                "companion-install-{}-{} ü 空",
                std::process::id(),
                ID.fetch_add(1, Ordering::SeqCst)
            ));
            let root = home.join("App bundle");
            fs::create_dir_all(&root).unwrap();
            let root = root.canonicalize().unwrap();
            let home = home.canonicalize().unwrap();
            let directory = home.join("user bin");
            let mut paths = vec![
                command_path("vaultwarden-cli"),
                command_path("companion-command"),
            ];
            paths.extend(match platform() {
                "macos" => vec![
                    "Contents/Frameworks/libcompanion_core.dylib".into(),
                    "Contents/MacOS/companion_slice".into(),
                    "Contents/Frameworks/App.framework/Versions/A/App".into(),
                    "Contents/Frameworks/FlutterMacOS.framework/Versions/A/FlutterMacOS".into(),
                ],
                "windows" => vec![
                    "companion_core.dll".into(),
                    "companion_slice.exe".into(),
                    "flutter_windows.dll".into(),
                    "msvcp140.dll".into(),
                    "vcruntime140.dll".into(),
                    "data/app.so".into(),
                    "data/icudtl.dat".into(),
                ],
                _ => vec![
                    "lib/libcompanion_core.so".into(),
                    "companion_slice".into(),
                    "lib/libflutter_linux_gtk.so".into(),
                    "lib/libapp.so".into(),
                    "data/icudtl.dat".into(),
                ],
            });
            if protected_bundle() {
                paths.push(command_path("vw-access"));
            }
            paths.extend(expected_provider_components().into_iter().map(command_path));
            let mut payloads = Vec::new();
            for relative in paths {
                let path = root.join(&relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                create_new(&path, b"synthetic fixture; never executed", true).unwrap();
                payloads.push(Payload {
                    sha256: if relative == "Contents/MacOS/companion_slice" {
                        String::new()
                    } else {
                        file_hash(&path).unwrap()
                    },
                    path: relative,
                    executable: true,
                });
            }
            let m = Manifest {
                schema: 1,
                command_abi: ABI,
                platform: platform().into(),
                architecture: std::env::consts::ARCH.into(),
                app_version: app_version().into(),
                core_version: env!("CARGO_PKG_VERSION").into(),
                cli_version: "0.5.4".into(),
                source_revision: "a".repeat(40),
                source_inputs_sha256: "b".repeat(64),
                entrypoint: "lib/main.dart".into(),
                commands: expected_commands()
                    .into_iter()
                    .map(|n| (n.clone(), command_path(&n)))
                    .collect(),
                roles: expected_roles(),
                payloads,
                links: BTreeMap::new(),
            };
            fs::create_dir_all(manifest_path(&root).parent().unwrap()).unwrap();
            fs::write(manifest_path(&root), serde_json::to_vec(&m).unwrap()).unwrap();
            Self {
                home,
                root,
                directory,
            }
        }
        fn change(&self, f: impl FnOnce(&mut Manifest)) {
            let path = manifest_path(&self.root);
            let mut m: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            f(&mut m);
            fs::write(path, serde_json::to_vec(&m).unwrap()).unwrap();
        }
        fn enable(&self) -> Result<String, String> {
            enable_in(&self.root, &self.directory, &self.home)
        }
    }
    #[test]
    fn versions_are_independent_and_platform_roles_are_closed() {
        let f = Fixture::new();
        assert!(validate(&f.root).is_ok());
        f.change(|m| m.cli_version = "7.9.3".into());
        assert!(validate(&f.root).is_ok());
        f.change(|m| {
            m.roles
                .insert("desktop_approval".into(), platform() != "macos");
        });
        assert!(validate(&f.root).is_err());
    }
    #[test]
    fn protected_commands_follow_platform_and_architecture() {
        let protected =
            cfg!(target_os = "linux") || cfg!(all(target_os = "macos", target_arch = "aarch64"));
        assert_eq!(protected_bundle(), protected);
        assert_eq!(
            expected_commands().contains(&"vw-access".to_owned()),
            protected
        );
        assert_eq!(expected_roles()["protected_requesting"], protected);
        assert_eq!(expected_roles()["protected_provider"], protected);
        assert_eq!(
            expected_provider_components().contains(&"vaultwarden-accessd"),
            protected
        );
        assert_eq!(
            expected_provider_components().contains(&"vaultwarden-access-exec"),
            cfg!(target_os = "linux")
        );
        let f = Fixture::new();
        assert!(validate(&f.root).is_ok());
        for role in ["protected_requesting", "protected_provider"] {
            let g = Fixture::new();
            g.change(|m| {
                m.roles.insert(role.into(), !protected);
            });
            assert!(validate(&g.root).is_err(), "{role}");
        }
        if protected {
            let h = Fixture::new();
            let accessd = command_path("vaultwarden-accessd");
            h.change(|m| m.payloads.retain(|p| p.path != accessd));
            fs::remove_file(h.root.join(&accessd)).unwrap();
            assert_eq!(
                validate(&h.root).unwrap_err(),
                "Missing required bundle component record"
            );
        }
    }
    #[test]
    fn incompatible_app_is_distinct_but_old_launcher_accepts_new_compatible_bundle() {
        let f = Fixture::new();
        f.change(|m| {
            m.app_version = "2.0.0+1".into();
            m.core_version = "2.0.0".into();
        });
        assert_eq!(inspect(&f.root, "").state, "incompatible");
        assert!(validate_contract(&f.root, false).is_ok());
        f.change(|m| m.command_abi = 2);
        assert!(validate_contract(&f.root, false).is_err());
    }
    #[test]
    fn omitted_required_component_and_extra_file_are_rejected() {
        let f = Fixture::new();
        f.change(|m| {
            m.payloads.remove(0);
        });
        assert!(validate(&f.root).is_err());
        let g = Fixture::new();
        fs::write(g.root.join("unexpected.dll"), b"untrusted").unwrap();
        assert!(validate(&g.root).is_err());
    }
    #[test]
    fn missing_damaged_and_path_escape_refuse_activation() {
        let f = Fixture::new();
        let command = f.root.join(command_path("vaultwarden-cli"));
        fs::remove_file(&command).unwrap();
        assert_eq!(inspect(&f.root, "").state, "missing");
        assert!(f.enable().is_err());
        fs::write(&command, b"replacement").unwrap();
        assert_eq!(inspect(&f.root, "").state, "damaged");
        f.change(|m| m.payloads[0].path = "../outside".into());
        assert!(validate(&f.root).is_err());
    }
    #[test]
    fn enable_repeat_move_and_failed_upgrade_preserve_previous_receipt() {
        let f = Fixture::new();
        f.enable().unwrap();
        f.enable().unwrap();
        let old = fs::read(f.directory.join(RECEIPT)).unwrap();
        let changed = Fixture::new();
        fs::write(
            changed.root.join(command_path("vaultwarden-cli")),
            b"damaged",
        )
        .unwrap();
        assert!(enable_in(&changed.root, &f.directory, &f.home).is_err());
        assert_eq!(fs::read(f.directory.join(RECEIPT)).unwrap(), old);
        let moved = f.home.join("Moved ü app");
        fs::rename(&f.root, &moved).unwrap();
        enable_in(&moved, &f.directory, &f.home).unwrap();
        assert_eq!(
            read_receipt(&f.directory.join(RECEIPT)).unwrap().bundle,
            moved
        );
        assert_eq!(fs::read(f.directory.join(PREVIOUS)).unwrap(), old);
    }
    #[test]
    fn unrelated_command_and_outside_home_are_not_changed() {
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        let cmd = f.directory.join(binary_name("vaultwarden-cli"));
        fs::write(&cmd, b"unrelated").unwrap();
        assert!(f.enable().is_err());
        assert_eq!(fs::read(cmd).unwrap(), b"unrelated");
        assert!(enable_in(&f.root, &std::env::temp_dir(), &f.home).is_err());
    }
    #[test]
    fn interrupted_first_activation_and_staged_upgrade_recover() {
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        // Kernel lock files and a fully published first launcher survive a crash.
        fs::write(f.directory.join(".vaultwarden-commands.lock"), b"").unwrap();
        let launcher = fs::read(f.root.join(command_path("companion-command"))).unwrap();
        create_new(
            &f.directory.join(binary_name("vaultwarden-cli")),
            &launcher,
            true,
        )
        .unwrap();
        f.enable().unwrap();
        fs::copy(
            f.directory.join(RECEIPT),
            f.directory.join(".vaultwarden-commands.next.json"),
        )
        .unwrap();
        f.enable().unwrap();
        // An unrelated/abandoned stage is never used as authority or deleted.
        assert!(f.directory.join(".vaultwarden-commands.next.json").exists());
    }
    #[cfg(unix)]
    #[test]
    fn hostile_stale_links_and_lost_modes_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        let command = f.directory.join(binary_name("vaultwarden-cli"));
        symlink("/missing-hostile-target", &command).unwrap();
        assert!(f.enable().is_err());
        assert!(command.symlink_metadata().unwrap().file_type().is_symlink());
        let target = f.root.join(command_path("vaultwarden-cli"));
        fs::set_permissions(target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate(&f.root).is_err());
    }
    #[test]
    fn path_candidates_are_reported_without_execution() {
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        create_new(
            &f.directory.join(binary_name("vaultwarden-cli")),
            b"must never execute",
            true,
        )
        .unwrap();
        let p = std::env::join_paths([&f.directory]).unwrap();
        assert_eq!(inspect(&f.root, p.to_str().unwrap()).state, "conflicting");
    }
    #[cfg(unix)]
    #[test]
    fn denied_directory_permission_preserves_active_receipt() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.enable().unwrap();
        let old = fs::read(f.directory.join(RECEIPT)).unwrap();
        fs::set_permissions(&f.directory, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(f.enable().is_err());
        assert_eq!(fs::read(f.directory.join(RECEIPT)).unwrap(), old);
        fs::set_permissions(&f.directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[test]
    fn malformed_partial_stage_cannot_block_repeat_repair() {
        let f = Fixture::new();
        f.enable().unwrap();
        fs::write(f.directory.join(".vaultwarden-stage-abandoned"), b"partial").unwrap();
        f.enable().unwrap();
        assert_eq!(
            fs::read(f.directory.join(".vaultwarden-stage-abandoned")).unwrap(),
            b"partial"
        );
    }

    #[test]
    fn future_schema_is_incompatible_even_with_new_fields() {
        let f = Fixture::new();
        let path = manifest_path(&f.root);
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data["schema"] = 99.into();
        data["new_contract_field"] = true.into();
        fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(inspect(&f.root, "").state, "incompatible");
    }
    #[test]
    fn earlier_relative_path_cannot_report_managed_command_as_unambiguous() {
        let f = Fixture::new();
        f.enable().unwrap();
        let p = std::env::join_paths([Path::new("."), f.directory.as_path()]).unwrap();
        let status = inspect(&f.root, p.to_str().unwrap());
        assert_eq!(status.state, "conflicting");
        assert!(status.detail.contains("relative PATH"));
        let empty = std::env::join_paths([Path::new(""), f.directory.as_path()]).unwrap();
        assert_eq!(
            inspect(&f.root, empty.to_str().unwrap()).state,
            "conflicting"
        );
    }
    #[test]
    fn architecture_transition_preserves_previous_setup() {
        let f = Fixture::new();
        f.enable().unwrap();
        let path = f.directory.join(RECEIPT);
        let mut receipt = read_receipt(&path).unwrap();
        receipt.architecture = if std::env::consts::ARCH == "aarch64" {
            "x86_64"
        } else {
            "aarch64"
        }
        .into();
        let old = serde_json::to_vec(&receipt).unwrap();
        fs::write(&path, &old).unwrap();
        assert!(f.enable().unwrap_err().contains("architecture differs"));
        assert_eq!(fs::read(path).unwrap(), old);
    }
    #[cfg(unix)]
    #[test]
    fn lost_execute_permission_replaces_only_managed_directory_entry() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.enable().unwrap();
        let command = f.directory.join(binary_name("vaultwarden-cli"));
        let unrelated = f.home.join("other hard link");
        fs::hard_link(&command, &unrelated).unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o644)).unwrap();
        f.enable().unwrap();
        assert_ne!(
            fs::metadata(&command).unwrap().permissions().mode() & 0o111,
            0
        );
        assert_eq!(
            fs::metadata(&unrelated).unwrap().permissions().mode() & 0o111,
            0
        );
        assert_eq!(fs::read(command).unwrap(), fs::read(unrelated).unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn writable_or_linked_ancestor_is_rejected_before_publication() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = Fixture::new();
        let parent = f.home.join("shared");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(enable_in(&f.root, &parent.join("private bin"), &f.home).is_err());
        assert!(!parent.join("private bin").exists());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let outside = f.home.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, parent.join("link")).unwrap();
        assert!(enable_in(&f.root, &parent.join("link/bin"), &f.home).is_err());
        assert!(!outside.join("bin").exists());
    }
    #[cfg(unix)]
    #[test]
    fn directory_swap_cannot_redirect_writes_to_unrelated_target() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let directory = Directory::open(&f.home, &f.directory, &f.root).unwrap();
        let moved = f.home.join("moved bin");
        fs::rename(&f.directory, &moved).unwrap();
        let outside = f.home.join("unrelated");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &f.directory).unwrap();
        let (manifest, digest) = validate(&f.root).unwrap();
        assert!(enable_locked(&f.root, &directory, &manifest, &digest).is_err());
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
        assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
    }
    #[test]
    fn post_switch_sync_failure_reports_active_new_setup_and_preserves_backup() {
        let f = Fixture::new();
        f.enable().unwrap();
        let g = Fixture::new();
        let mut directory = Directory::open(&f.home, &f.directory, &g.root).unwrap();
        directory.fail_final_sync = true;
        let (manifest, digest) = validate(&g.root).unwrap();
        let message = enable_locked(&g.root, &directory, &manifest, &digest).unwrap();
        assert!(message.contains("new command setup is active"));
        assert_eq!(
            read_receipt(&f.directory.join(RECEIPT)).unwrap().bundle,
            g.root
        );
        assert_eq!(
            read_receipt(&f.directory.join(PREVIOUS)).unwrap().bundle,
            f.root
        );
    }
    #[test]
    fn corrupt_active_setup_is_quarantined_when_previous_setup_is_valid() {
        let f = Fixture::new();
        f.enable().unwrap();
        let g = Fixture::new();
        enable_in(&g.root, &f.directory, &f.home).unwrap();
        fs::write(f.directory.join(RECEIPT), b"unexplained damaged data").unwrap();
        enable_in(&g.root, &f.directory, &f.home).unwrap();
        assert_eq!(
            read_receipt(&f.directory.join(RECEIPT)).unwrap().bundle,
            g.root
        );
        let retained: Vec<_> = fs::read_dir(&f.directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".vaultwarden-quarantine-")
            })
            .collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(fs::read(&retained[0]).unwrap(), b"unexplained damaged data");
    }
    #[cfg(windows)]
    #[test]
    fn windows_open_ancestors_cannot_be_renamed() {
        let f = Fixture::new();
        let parent = f.home.join("parent");
        let nested = parent.join("bin");
        let _directory = Directory::open(&f.home, &nested, &f.root).unwrap();
        assert!(fs::rename(&parent, f.home.join("moved")).is_err());
    }

    #[test]
    fn forged_receipt_cannot_bless_an_unrelated_command() {
        let f = Fixture::new();
        f.enable().unwrap();
        let path = f.directory.join(RECEIPT);
        let mut receipt = read_receipt(&path).unwrap();
        let hostile = b"unrelated executable must never run or be retained";
        fs::write(f.directory.join(binary_name("vaultwarden-cli")), hostile).unwrap();
        receipt.launcher_sha256 = hash(hostile);
        let forged = serde_json::to_vec(&receipt).unwrap();
        fs::write(&path, &forged).unwrap();
        assert!(f.enable().unwrap_err().contains("cannot be verified"));
        assert_eq!(fs::read(path).unwrap(), forged);
        assert_eq!(
            fs::read(f.directory.join(binary_name("vaultwarden-cli"))).unwrap(),
            hostile
        );
    }
    #[test]
    fn valid_original_bundle_proves_retained_launcher_across_repeated_upgrade_repair() {
        let f = Fixture::new();
        f.enable().unwrap();
        let g = Fixture::new();
        let path = g.root.join(command_path("companion-command"));
        fs::write(&path, b"new compatible launcher build").unwrap();
        g.change(|m| {
            m.payloads
                .iter_mut()
                .find(|p| p.path == command_path("companion-command"))
                .unwrap()
                .sha256 = file_hash(&path).unwrap()
        });
        let old_bytes = fs::read(f.directory.join(binary_name("vaultwarden-cli"))).unwrap();
        enable_in(&g.root, &f.directory, &f.home).unwrap();
        enable_in(&g.root, &f.directory, &f.home).unwrap();
        let current = read_receipt(&f.directory.join(RECEIPT)).unwrap();
        assert_eq!(current.bundle, g.root);
        assert_eq!(current.launcher_bundle, f.root);
        assert_eq!(
            current.launcher_manifest_sha256,
            validate(&f.root).unwrap().1
        );
        assert_eq!(
            fs::read(f.directory.join(binary_name("vaultwarden-cli"))).unwrap(),
            old_bytes
        );
        // Losing the original proof never licenses the receipt to bless a file.
        fs::remove_dir_all(&f.root).unwrap();
        let before = fs::read(f.directory.join(RECEIPT)).unwrap();
        assert!(enable_in(&g.root, &f.directory, &f.home)
            .unwrap_err()
            .contains("new empty user folder"));
        assert_eq!(fs::read(f.directory.join(RECEIPT)).unwrap(), before);
    }

    #[test]
    fn missing_active_setup_is_restored_from_valid_previous_setup() {
        let f = Fixture::new();
        f.enable().unwrap();
        fs::copy(f.directory.join(RECEIPT), f.directory.join(PREVIOUS)).unwrap();
        fs::remove_file(f.directory.join(RECEIPT)).unwrap();
        f.enable().unwrap();
        assert_eq!(
            read_receipt(&f.directory.join(RECEIPT)).unwrap().bundle,
            f.root
        );
    }
    #[cfg(unix)]
    #[test]
    fn other_users_execute_bits_do_not_satisfy_owner_execution() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.enable().unwrap();
        let command = f.directory.join(binary_name("vaultwarden-cli"));
        for mode in [0o641, 0o654] {
            fs::set_permissions(&command, fs::Permissions::from_mode(mode)).unwrap();
            f.enable().unwrap();
            assert_ne!(
                fs::metadata(&command).unwrap().permissions().mode() & 0o100,
                0
            );
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_acl_mutation_grants_are_rejected_but_deny_delete_is_allowed() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        fs::set_permissions(&f.directory, fs::Permissions::from_mode(0o700)).unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow search,add_file,delete_child"])
            .arg(&f.directory)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(f.enable().unwrap_err().contains("ACL"));
        assert!(!f.directory.join(RECEIPT).exists());
        assert!(std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&f.directory)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone deny delete"])
            .arg(&f.directory)
            .status()
            .unwrap()
            .success());
        f.enable().unwrap();
        assert!(std::process::Command::new("/bin/chmod")
            .arg("-N")
            .arg(&f.directory)
            .status()
            .unwrap()
            .success());
    }
    #[cfg(windows)]
    #[test]
    fn windows_inherit_only_untrusted_file_write_grant_is_rejected() {
        let f = Fixture::new();
        fs::create_dir(&f.directory).unwrap();
        let tool =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/icacls.exe");
        assert!(std::process::Command::new(tool)
            .arg(&f.directory)
            .args(["/grant", "*S-1-1-0:(OI)(IO)(W)"])
            .status()
            .unwrap()
            .success());
        assert!(f.enable().is_err());
        assert!(!f.directory.join(RECEIPT).exists());
    }
    /// Runs only after a real normal-entry release has been assembled. The
    /// copied production launcher performs its own signature/inventory checks.
    #[test]
    #[ignore = "requires the freshly packaged application; desktop gate invokes explicitly"]
    fn packaged_bundle_command_invocation() {
        let root =
            PathBuf::from(std::env::var_os("COMPANION_TEST_BUNDLE").expect("bundle path required"))
                .canonicalize()
                .unwrap();
        let f = Fixture::new();
        enable_in(&root, &f.directory, &f.home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                f.directory.join(binary_name("vaultwarden-cli")),
                fs::Permissions::from_mode(0o641),
            )
            .unwrap();
        }
        enable_in(&root, &f.directory, &f.home).unwrap();
        for name in expected_commands() {
            let output = std::process::Command::new(f.directory.join(binary_name(&name)))
                .arg("--version")
                .current_dir(&f.home)
                .env("PATH", "")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout)
                .contains(&validate(&root).unwrap().0.cli_version));
        }
        #[cfg(target_os = "linux")]
        {
            let fixture = Fixture::new();
            let native = fs::read(root.join(command_path("companion-command"))).unwrap();
            fs::write(fixture.root.join(command_path("companion-command")), native).unwrap();
            let script = b"#!/bin/sh\nprintf '%s\\n' \"$$\"\n";
            fs::write(fixture.root.join(command_path("vaultwarden-cli")), script).unwrap();
            fixture.change(|m| {
                for payload in &mut m.payloads {
                    payload.sha256 = file_hash(&fixture.root.join(&payload.path)).unwrap();
                }
            });
            fixture.enable().unwrap();
            let child =
                std::process::Command::new(fixture.directory.join(binary_name("vaultwarden-cli")))
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
            let expected = child.id();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap().trim(),
                expected.to_string()
            );
        }
        fs::write(f.directory.join(RECEIPT), b"damaged").unwrap();
        let output = std::process::Command::new(f.directory.join(binary_name("vaultwarden-cli")))
            .arg("--version")
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}
