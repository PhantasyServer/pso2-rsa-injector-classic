mod process_manip;
use core::slice;
use detour::GenericDetour;
use parking_lot::RwLock;
use process_manip::{ModuleSnapshot, PrintWindowOption, PrintWindowResult, ProcessSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    mem,
    net::{Ipv4Addr, TcpStream},
    path::PathBuf,
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS},
        Networking::WinSock::ADDRINFOA,
        Security::Cryptography::{BCRYPT_KEY_HANDLE, CRYPT_KEY_FLAGS},
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        },
    },
};

/// Injector settings
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    /// Path to user provided public key
    user_key: String,
    /// Enables address replacement feature
    replace_address: bool,
    /// Enables auto public key exchange
    auto_key_fetch: bool,
    /// Fixes incorrect `BCryptExportKey` behavior on wine
    classic_wine_fix: bool,
    /// Disables MD5 hashing of game file names and automatically moves them to their correct
    /// folders
    unmd5: bool,
    /// List of addresses to replace
    addresses: Vec<AddrReplace>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            replace_address: false,
            user_key: "publicKey.blob".to_string(),
            auto_key_fetch: false,
            classic_wine_fix: false,
            unmd5: false,
            addresses: vec![AddrReplace::default()],
        }
    }
}

/// Ship address to be replaced
#[derive(Serialize, Deserialize)]
struct AddrReplace {
    old: String,
    new: String,
}
impl Default for AddrReplace {
    fn default() -> Self {
        AddrReplace {
            old: "old_address".to_string(),
            new: "new_address".to_string(),
        }
    }
}

/// Structure for auto exchanged keys
#[derive(Serialize, Deserialize, Debug)]
struct Keys {
    ip: Ipv4Addr,
    key: Vec<u8>,
}

// consists of BLOBHEADER + RSAPUBKEY.magic
static RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];

// scraped RSA keys from the game
static SEGARSAKEYS: RwLock<Vec<Vec<u8>>> = RwLock::new(vec![]);
// user provided RSA key
static USERRSAKEYS: RwLock<Vec<u8>> = RwLock::new(vec![]);
// RSA keys provided by the server
static SHIPRSAKEYS: RwLock<Vec<Keys>> = RwLock::new(vec![]);
// injector settings
static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

// detours for functions
static HOOK_CRYPT_OPEN: RwLock<Option<GenericDetour<CryptImportKeyFn>>> = RwLock::new(None);
static HOOK_CRYPT_EXPORT: RwLock<Option<GenericDetour<BCryptExportKey>>> = RwLock::new(None);
static HOOK_GETADDRINFO: RwLock<Option<GenericDetour<GetaddrinfoFn>>> = RwLock::new(None);
static HOOK_MD5: RwLock<Option<GenericDetour<MD5Fn>>> = RwLock::new(None);

// text file of unhashed file names
static MD5_NAMES: RwLock<Option<std::fs::File>> = RwLock::new(None);

// detoured function types
type BCryptExportKey = extern "system" fn(
    BCRYPT_KEY_HANDLE,
    BCRYPT_KEY_HANDLE,
    PCWSTR,
    *mut u8,
    u32,
    *mut u32,
    u32,
) -> NTSTATUS;

type CryptImportKeyFn =
    extern "system" fn(usize, *const u8, u32, usize, CRYPT_KEY_FLAGS, *mut usize) -> bool;

type GetaddrinfoFn = extern "system" fn(PCSTR, PCSTR, *const ADDRINFOA, *mut *mut ADDRINFOA) -> i32;

type MD5Fn = extern "system" fn(u64, *const i8) -> *const i8;

// macro to detour a function
macro_rules! create_hook {
    ($dll_name:expr, $fn_name:expr => $new_fn:ident: $fn_type:ty) => {
        (|| -> Result<GenericDetour<_>, Box<dyn Error>> {
            let dll_name_u16: Vec<u16> =
                $dll_name.encode_utf16().chain(std::iter::once(0)).collect();
            let fn_name_u8: Vec<u8> = $fn_name.bytes().chain(std::iter::once(0)).collect();
            let proc_addr = {
                let handle = LoadLibraryW(PCWSTR::from_raw(dll_name_u16.as_ptr()))?;
                GetProcAddress(handle, PCSTR::from_raw(fn_name_u8.as_ptr()))
                    .ok_or("No function found")?
            };

            let orig: $fn_type = mem::transmute(proc_addr);
            let hooked_fn = GenericDetour::new(orig, $new_fn)?;
            hooked_fn.enable()?;
            Ok(hooked_fn)
        })()
    };
}

// DLL entry point, called by the injector
#[no_mangle]
extern "system" fn init() {
    run_init().unwrap_window();
}

fn run_init() -> Result<(), Box<dyn Error>> {
    let path = get_base_dir("pso2.exe")?.unwrap_or_default();
    if check_ngs(&path) {
        process_manip::print_msgbox(
            "This RSA injector is only for the classic version of the game",
            "Invalid version",
        );
        return Ok(());
    }
    let settings = read_settings(&path);
    if !settings.user_key.is_empty() {
        let key_path = std::path::PathBuf::from(&settings.user_key);
        let key_path = if key_path.is_absolute() {
            key_path
        } else {
            path.join(key_path)
        };
        if let Ok(mut x) = File::open(&key_path) {
            x.read_to_end(USERRSAKEYS.write().as_mut())?;
        }
    }

    if !settings.user_key.is_empty() || settings.auto_key_fetch {
        // SAFETY: `crypt_open_stub` signature matches the actual function
        *HOOK_CRYPT_OPEN.write() = Some(unsafe {
            create_hook!(
                    "advapi32.dll", "CryptImportKey" =>
                    crypt_open_stub: CryptImportKeyFn
            )?
        });
    }

    if settings.classic_wine_fix {
        // SAFETY: `export_stub` signature matches the actual function
        *HOOK_CRYPT_EXPORT.write() = Some(unsafe {
            create_hook!(
                    "bcrypt.dll", "BCryptExportKey" =>
                    export_stub: BCryptExportKey
            )?
        });
    }
    if settings.replace_address {
        // SAFETY: `getaddrinfo_stub` signature matches the actual function
        *HOOK_GETADDRINFO.write() = Some(unsafe {
            create_hook!(
                    "Ws2_32.dll", "getaddrinfo" =>
                    getaddrinfo_stub: GetaddrinfoFn
            )?
        });
    }

    // GG check
    // CALL XXX, search by [33 c9 3d 55 07 00 00] offset from beginning: -5
    let pattern = &[0x33, 0xC9, 0x3D, 0x55, 0x07, 0x00, 0x00];
    if let Some(ptr) = find_pattern(pattern)? {
        // SAFETY:
        // 1) ptr points to valid memory
        // 2) data doesn't overflow memory
        unsafe { replace_at(ptr - 5, &[0xB8, 0x55, 0x07, 0x00])? };
    }

    // GG load
    // JNZ XXX, search by [48 33 c4 48 89 85 90 1b 00 00 80 39 00] offset from end: 6
    let pattern = &[
        0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x90, 0x1b, 0x00, 0x00, 0x80, 0x39, 0x00,
    ];
    if let Some(ptr) = find_pattern(pattern)? {
        // SAFETY:
        // 1) ptr points to valid memory
        // 2) data doesn't overflow memory
        unsafe {
            replace_at(
                ptr + pattern.len() + 6,
                &[0xE9, 0x58, 0x23, 0x00, 0x00, 0x90],
            )?
        };
    }

    if let Some(x) = get_rsa_key()? {
        *SEGARSAKEYS.write() = x
    }

    // MD5 calculation
    if settings.unmd5 {
        let pattern = &[
            0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24,
            0x18, 0x48, 0x89, 0x7c, 0x24, 0x20, 0x41, 0x56, 0x48, 0x81, 0xec, 0xa0, 0x00, 0x00,
            0x00, 0x8b, 0x0d, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8b, 0xda,
        ];
        if let Some(ptr) = find_pattern(pattern)? {
            *MD5_NAMES.write() = Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("hashed.txt")
                    .unwrap_window(),
            );
            // SAFETY: ptr points to a valid MD5 function
            let orig_import: MD5Fn = unsafe { mem::transmute(ptr) };
            // SAFETY:
            // 1) orig_import is a valid function
            // 2) md5_stub has the same signature
            let hooked_fn = unsafe { GenericDetour::new(orig_import, md5_stub)? };
            unsafe { hooked_fn.enable()? };
            *HOOK_MD5.write() = Some(hooked_fn);
        }
    }
    *SETTINGS.write() = Some(settings);
    Ok(())
}

fn find_pattern(bytes: &[u8]) -> Result<Option<usize>, windows::core::Error> {
    let pid = get_process("pso2.exe")?.unwrap();
    let Some(data) = get_module_mem(pid, "pso2.exe")? else {
        return Ok(None);
    };
    let data_ptr = data.as_ptr();
    'outer: for i in 0..data.len() {
        let new_ptr = unsafe { data_ptr.add(i) };
        for (ii, byte) in bytes.iter().enumerate() {
            if *byte != 0xFF && data[i + ii] != *byte {
                continue 'outer;
            }
        }
        return Ok(Some(new_ptr as usize));
    }
    Ok(None)
}

// SAFETY:
// 1) `offset` must point to a valid location in the process memory
// 2) `bytes` must not overflow the data at offset
unsafe fn replace_at(offset: usize, bytes: &[u8]) -> Result<(), windows::core::Error> {
    let data_ptr = offset as *mut u8;
    // SAFETY: data_ptr points to a valid memory location (caller contract)
    let data = unsafe { &mut *std::ptr::slice_from_raw_parts_mut::<u8>(data_ptr, bytes.len()) };
    let mut old_flags = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        let _ = VirtualProtect(
            data_ptr.add(offset) as _,
            bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_flags,
        );
        data[..bytes.len()].copy_from_slice(bytes);
    }

    Ok(())
}

/// Removes hashing of game file names
///
/// Stubs game MD5 function
extern "system" fn md5_stub(a: u64, input: *const i8) -> *const i8 {
    let hook_lock = HOOK_MD5.read();
    let output = hook_lock.as_ref().unwrap_window().call(a, input);
    // SAFETY: input is a valid c string
    let filename = unsafe { std::ffi::CStr::from_ptr(input) }
        .to_str()
        .unwrap_window();
    // SAFETY: output is a valid c string
    let hash = unsafe { std::ffi::CStr::from_ptr(output) }
        .to_str()
        .unwrap_window();

    fn move_file(base_dir: &str, filename: &str, hash: &str) {
        let mut orig_filename = std::path::PathBuf::from(base_dir);
        let mut new_filename = orig_filename.clone();
        orig_filename.push(hash);
        new_filename.push(filename);
        let mut file_path = new_filename.clone();
        file_path.pop();
        if !new_filename.exists() && orig_filename.is_file() {
            std::fs::create_dir_all(&file_path).unwrap_window();
            std::fs::rename(&orig_filename, &new_filename).unwrap_window();
            let mut file = MD5_NAMES.write();
            let file = file.as_mut().unwrap_window();
            writeln!(file, "{hash}:{filename}").unwrap_window();
        }
    }

    move_file("data/win32", filename, hash);
    move_file("data/win32_na", filename, hash);
    drop(hook_lock);
    input
}

fn read_settings(path: &std::path::Path) -> Settings {
    let path = path.join("config.toml");
    let mut file = match File::options().read(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            process_manip::print_msgbox(
                &format!("Failed to open settings file: {e}, creating default file"),
                "Read settings failed",
            );
            let set = Default::default();
            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap_window();
            file.write_all(toml::to_string(&set).unwrap_window().as_bytes())
                .unwrap_window();
            return set;
        }
    };
    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string).unwrap_window();

    match toml::from_str(&toml_string) {
        Ok(s) => s,
        Err(e) => {
            process_manip::print_msgbox(
                &format!("Failed to parse settings file: {e}, using defaults"),
                "Read settings failed",
            );
            Default::default()
        }
    }
}

/// Replaces the original RSA key
///
/// Stubs `CryptImportKey`
extern "system" fn crypt_open_stub(
    hprov: usize,
    pbdata: *const u8,
    dwdatalen: u32,
    hpubkey: usize,
    dwflags: CRYPT_KEY_FLAGS,
    phkey: *mut usize,
) -> bool {
    if pbdata.is_null() || dwdatalen == 0 {
        let hook_lock = HOOK_CRYPT_OPEN.read();
        return hook_lock
            .as_ref()
            .unwrap()
            .call(hprov, pbdata, dwdatalen, hpubkey, dwflags, phkey);
    }
    let user_key = USERRSAKEYS.read();
    let mut data_location = (pbdata, dwdatalen);
    if !user_key.is_empty() {
        // SAFETY: 1) pbdata is not nullptr
        // 2) here we work with bytes, so they are alligned
        // 3) pbdata must point to a valid PUBLICKEYSTRUC blob
        let orig_key = unsafe { slice::from_raw_parts_mut(pbdata as *mut u8, dwdatalen as usize) };
        {
            let mut keys = SEGARSAKEYS.write();
            if keys.is_empty() {
                if let Some(x) = get_rsa_key().unwrap_window() {
                    *keys = x;
                }
            };
        }
        for key in SEGARSAKEYS.read().iter() {
            if key.len() != dwdatalen as usize {
                continue;
            }
            if orig_key.iter().zip(key.iter()).any(|x| *x.0 != *x.1) {
                continue;
            }
            data_location.0 = user_key.as_ptr();
            data_location.1 = user_key.len() as u32;
            break;
        }
    }

    let hook_lock = HOOK_CRYPT_OPEN.read();
    hook_lock.as_ref().unwrap().call(
        hprov,
        data_location.0,
        data_location.1,
        hpubkey,
        dwflags,
        phkey,
    )
}

/// Wine fixes
///
/// Stubs `BCryptExportKey`
extern "system" fn export_stub(
    hkey: BCRYPT_KEY_HANDLE,
    hexportkey: BCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    dwflags: u32,
) -> NTSTATUS {
    let hook_lock = HOOK_CRYPT_EXPORT.read();
    let mut result = hook_lock.as_ref().unwrap().call(
        hkey,
        hexportkey,
        pszblobtype,
        pboutput,
        cboutput,
        pcbresult,
        dwflags,
    );
    if pboutput.is_null() && result == STATUS_BUFFER_TOO_SMALL {
        result = STATUS_SUCCESS;
    }
    result
}

/// Address replacement and key replacement
///
/// Stubs `getaddrinfo`
extern "system" fn getaddrinfo_stub(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    if pnodename.is_null() {
        let hook_lock = HOOK_GETADDRINFO.read();
        return hook_lock
            .as_ref()
            .unwrap()
            .call(pnodename, pservicename, phints, ppresult);
    }

    let settings_lock = SETTINGS.read();
    let settings = settings_lock.as_ref().unwrap_window();
    //SAFETY: 1) pnodename is not null
    //2) pnodename should be valid up to and including a `\0` byte
    let mut addr_in = unsafe { pnodename.to_string().unwrap_window() };
    let mut is_changed = false;
    for addr in &settings.addresses {
        if addr_in.contains(&addr.old) {
            addr_in = addr.new.to_string();
            is_changed = true;
            break;
        }
    }
    if settings.auto_key_fetch && is_changed {
        unsafe {
            HOOK_GETADDRINFO
                .write()
                .as_mut()
                .unwrap()
                .disable()
                .unwrap_window()
        };
        // auto key negotiation
        if let Ok(mut socket) = TcpStream::connect((addr_in.as_str(), 11000)) {
            // read structure len
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).unwrap_window();
            let len = u32::from_le_bytes(len);

            // read serialized keys
            let mut data = vec![0u8; len as usize];
            socket.read_exact(&mut data).unwrap_window();
            let keys = match rmp_serde::from_slice::<Vec<Keys>>(&data) {
                Ok(k) => k,
                Err(e) => {
                    process_manip::print_msgbox(
                        &format!("Failed to parse keys: {e}"),
                        "Key negotiation failed",
                    );
                    Default::default()
                }
            };
            *SHIPRSAKEYS.write() = keys;
        }
        unsafe {
            HOOK_GETADDRINFO
                .write()
                .as_mut()
                .unwrap()
                .enable()
                .unwrap_window()
        };
    }

    // key replacement
    if let Ok(addr) = addr_in.parse::<Ipv4Addr>() {
        let lock = SHIPRSAKEYS.read();
        let key = lock.iter().find(|k| k.ip == addr);
        if let Some(key) = key {
            *USERRSAKEYS.write() = key.key.clone();
        }
    }
    let addr_in = CString::new(addr_in).unwrap_window();
    let hook_lock = HOOK_GETADDRINFO.read();
    hook_lock.as_ref().unwrap().call(
        PCSTR::from_raw(addr_in.as_ptr() as *const u8),
        pservicename,
        phints,
        ppresult,
    )
}

fn get_rsa_key() -> Result<Option<Vec<Vec<u8>>>, windows::core::Error> {
    let pid = get_process("pso2.exe")?.unwrap();
    let Some(data) = get_module_mem(pid, "pso2.exe")? else {
        return Ok(None);
    };
    let mut keys: Vec<Vec<u8>> = vec![];

    // key structure information
    // https://learn.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs

    let header_len = RSAHEADER.len();
    for i in 0..data.len() - header_len {
        let tmp_data = &data[i..i + header_len];
        if tmp_data == RSAHEADER {
            let data = &data[i..];
            let key_len = u32::from_le_bytes(data[header_len..header_len + 4].try_into().unwrap());
            // +4 - key bit length field
            // +4 - public exponent field
            let byte_len = key_len as usize / 8 + 4 + 4 + header_len;
            let data = &data[..byte_len];
            keys.push(data.to_vec());
        }
    }

    Ok(Some(keys))
}

fn get_base_dir(process_name: &str) -> Result<Option<PathBuf>, windows::core::Error> {
    let Some(pid) = get_process(process_name)? else {
        return Ok(None);
    };
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        let module = module?;
        if module.module_name == process_name {
            let mut exe_path = std::path::PathBuf::from(module.module_path);
            exe_path.pop();
            return Ok(Some(exe_path));
        }
    }
    Ok(None)
}

fn get_process(process_name: &str) -> Result<Option<u32>, windows::core::Error> {
    let processes = ProcessSnapshot::new()?;
    for process in processes {
        let process = process?;
        if process.process_name == process_name {
            return Ok(Some(process.pid));
        }
    }
    Ok(None)
}

fn get_module_mem(pid: u32, module_name: &str) -> Result<Option<&mut [u8]>, windows::core::Error> {
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        let module = module?;
        if module.module_name == module_name {
            return Ok(Some(unsafe { module.get_memory_mut() }));
        }
    }
    Ok(None)
}

fn check_ngs(path: &std::path::Path) -> bool {
    let mut path = match fs::metadata(path.join("pso2_bin")) {
        Ok(x) if x.is_dir() => path.join("pso2_bin"),
        Ok(_) | Err(_) => path.to_owned(),
    };
    path.push("pso2reboot.dll");
    if fs::metadata(path).is_ok() {
        return true;
    }
    false
}
