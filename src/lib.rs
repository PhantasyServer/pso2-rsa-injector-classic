pub mod process_manip;
use core::slice;
use detour::{Function, GenericDetour};
use process_manip::{ModuleSnapshot, PrintWindowOption, PrintWindowResult, ProcessSnapshot};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::{self, Read, Write},
    mem,
    net::{Ipv4Addr, TcpStream},
    path::PathBuf,
    sync::{Mutex, RwLock},
};
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{
            FreeLibrary, FARPROC, HMODULE, NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS,
        },
        Networking::WinSock::ADDRINFOA,
        Security::Cryptography::{
            BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
            CRYPT_KEY_FLAGS,
        },
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        },
    },
};

#[derive(Serialize, Deserialize)]
struct Settings {
    user_key: String,
    grab_keys: bool,
    replace_address: bool,
    auto_key_fetch: bool,
    addresses: Vec<AddrReplace>,
    classic_wine_fix: bool,
    unmd5: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            grab_keys: true,
            replace_address: false,
            user_key: "publicKey.blob".to_string(),
            auto_key_fetch: false,
            addresses: vec![AddrReplace::default()],
            classic_wine_fix: false,
            unmd5: false,
        }
    }
}
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

#[derive(Serialize, Deserialize, Debug)]
struct Keys {
    ip: Ipv4Addr,
    key: Vec<u8>,
}

static RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];

static SEGARSAKEYS: RwLock<Vec<Vec<u8>>> = RwLock::new(vec![]);
static USERRSAKEYS: RwLock<Vec<u8>> = RwLock::new(vec![]);
static SHIPRSAKEYS: RwLock<Vec<Keys>> = RwLock::new(vec![]);
static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

static HOOK_OPEN: RwLock<Option<GenericDetour<OpenAlgorithmProviderFn>>> = RwLock::new(None);
static HOOK_CRYPT_OPEN: RwLock<Option<GenericDetour<CryptImportKeyFn>>> = RwLock::new(None);
static HOOK_CRYPT_EXPORT: RwLock<Option<GenericDetour<BCryptExportKey>>> = RwLock::new(None);
static HOOK_GETADDRINFO: RwLock<Option<GenericDetour<GetaddrinfoFn>>> = RwLock::new(None);
static HOOK_MD5: RwLock<Option<GenericDetour<MD5Fn>>> = RwLock::new(None);
static MD5_NAMES: RwLock<Option<std::fs::File>> = RwLock::new(None);

static PATH: RwLock<Option<std::path::PathBuf>> = RwLock::new(None);
static HANDLES: Mutex<Vec<HMODULE>> = Mutex::new(vec![]);

type OpenAlgorithmProviderFn = extern "system" fn(
    *mut BCRYPT_ALG_HANDLE,
    PCWSTR,
    PCWSTR,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) -> NTSTATUS;

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

#[no_mangle]
extern "system" fn init() {
    run_init().unwrap_window();
}

fn run_init() -> Result<(), Box<dyn Error>> {
    unsafe {
        if let Some(dir) = get_base_dir("pso2.exe")? {
            *PATH.write()? = Some(PathBuf::from(dir));
        } else {
            *PATH.write()? = Some(PathBuf::new());
        }
        if check_ngs() {
            process_manip::print_msgbox(
                "This RSA injector is only for the classic version of the game",
                "Invalid version",
            );
            return Ok(());
        }
        *SETTINGS.write()? = Some(read_settings());
        let settings_lock = SETTINGS.read()?;
        let settings = settings_lock.as_ref().unwrap_window();
        if !settings.user_key.is_empty() {
            let key_path = std::path::PathBuf::from(&settings.user_key);
            let key_path = if key_path.is_absolute() {
                key_path
            } else {
                PATH.read()?.as_ref().unwrap_window().join(key_path)
            };
            if let Ok(mut x) = File::open(&key_path) {
                x.read_to_end(USERRSAKEYS.write()?.as_mut())?;
            }
        }
        if !settings.user_key.is_empty() || settings.auto_key_fetch {
            let orig_import: CryptImportKeyFn =
                mem::transmute(load_fn("advapi32.dll", "CryptImportKey")?.unwrap_window());
            *HOOK_CRYPT_OPEN.write()? = Some(create_hook(orig_import, crypt_open_stub)?);
        }
        if settings.classic_wine_fix {
            let orig_import: BCryptExportKey =
                mem::transmute(load_fn("bcrypt.dll", "BCryptExportKey")?.unwrap_window());
            *HOOK_CRYPT_EXPORT.write()? = Some(create_hook(orig_import, export_stub)?);
        }
        if settings.replace_address {
            let orig_getaddrinfo: GetaddrinfoFn =
                mem::transmute(load_fn("Ws2_32.dll", "getaddrinfo")?.unwrap_window());
            *HOOK_GETADDRINFO.write()? = Some(create_hook(orig_getaddrinfo, getaddrinfo_stub)?);
        }

        // GG check
        // CALL XXX, search by [33 c9 3d 55 07 00 00] offset from beginning: -5
        let pattern = &[0x33, 0xC9, 0x3D, 0x55, 0x07, 0x00, 0x00];
        if let Some(ptr) = find_pattern(pattern)? {
            replace_at(ptr - 5, &[0xB8, 0x55, 0x07, 0x00])?;
        }

        // GG load
        // JNZ XXX, search by [48 33 c4 48 89 85 90 1b 00 00 80 39 00] offset from end: 6
        let pattern = &[
            0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x90, 0x1b, 0x00, 0x00, 0x80, 0x39, 0x00,
        ];
        if let Some(ptr) = find_pattern(pattern)? {
            replace_at(
                ptr + pattern.len() + 6,
                &[0xE9, 0x58, 0x23, 0x00, 0x00, 0x90],
            )?;
        }

        match get_rsa_key()? {
            Some(x) => *SEGARSAKEYS.write()? = x,
            None => {
                let orig_import: OpenAlgorithmProviderFn = mem::transmute(
                    load_fn("bcrypt.dll", "BCryptOpenAlgorithmProvider")?.unwrap_window(),
                );
                *HOOK_OPEN.write()? = Some(create_hook(orig_import, open_stub)?);
            }
        }
        // MD5 calculation
        if settings.unmd5 {
            let pattern = &[
                0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24,
                0x18, 0x48, 0x89, 0x7c, 0x24, 0x20, 0x41, 0x56, 0x48, 0x81, 0xec, 0xa0, 0x00, 0x00,
                0x00, 0x8b, 0x0d, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8b, 0xda,
            ];
            if let Some(ptr) = find_pattern(pattern)? {
                *MD5_NAMES.write().unwrap_window() = Some(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open("hashed.txt")
                        .unwrap_window(),
                );
                let orig_import: MD5Fn = mem::transmute(ptr);
                *HOOK_MD5.write()? = Some(create_hook(orig_import, md5_stub)?);
            }
        }
    }
    Ok(())
}

fn find_pattern(bytes: &[u8]) -> Result<Option<usize>, windows::core::Error> {
    let pid = get_process("pso2.exe")?.unwrap();
    let Some(data) = get_module(pid, "pso2.exe")? else {
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

fn replace_at(offset: usize, bytes: &[u8]) -> Result<(), windows::core::Error> {
    let data_ptr = offset as *mut u8;
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

extern "system" fn md5_stub(a: u64, input: *const i8) -> *const i8 {
    let hook_lock = HOOK_MD5.read().unwrap_window();
    let output = hook_lock.as_ref().unwrap_window().call(a, input);
    let filename = unsafe { std::ffi::CStr::from_ptr(input) }
        .to_str()
        .unwrap_window();
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
            let mut file = MD5_NAMES.write().unwrap_window();
            let file = file.as_mut().unwrap_window();
            write!(file, "{hash}:{filename}\n").unwrap_window();
        }
    }
    move_file("data/win32", filename, hash);
    move_file("data/win32_na", filename, hash);
    drop(hook_lock);
    input
}

fn read_settings() -> Settings {
    let path = PATH
        .read()
        .unwrap_window()
        .as_ref()
        .unwrap_window()
        .join("config.toml");
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)
        .unwrap_window();
    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string).unwrap_window();
    let settings: Settings = toml::from_str(&toml_string).unwrap_or_default();
    drop(file);
    let mut file = File::options()
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap_window();
    file.write_all(toml::to_string(&settings).unwrap_window().as_bytes())
        .unwrap_window();
    settings
}

extern "system" fn crypt_open_stub(
    hprov: usize,
    pbdata: *const u8,
    dwdatalen: u32,
    hpubkey: usize,
    dwflags: CRYPT_KEY_FLAGS,
    phkey: *mut usize,
) -> bool {
    let user_key = USERRSAKEYS.read().unwrap_window();
    let mut data_location = (pbdata, dwdatalen);
    let orig_key = unsafe { slice::from_raw_parts_mut(pbdata as *mut u8, dwdatalen as usize) };
    if !user_key.is_empty() {
        {
            let mut keys = SEGARSAKEYS.write().unwrap_window();
            if keys.len() == 0 {
                if let Some(x) = get_rsa_key().unwrap_window() {
                    *keys = x;
                }
            };
        }
        for key in SEGARSAKEYS.read().unwrap_window().iter() {
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

    let hook_lock = HOOK_CRYPT_OPEN.read().unwrap_window();
    hook_lock.as_ref().unwrap().call(
        hprov,
        data_location.0,
        data_location.1,
        hpubkey,
        dwflags,
        phkey,
    )
}

extern "system" fn export_stub(
    hkey: BCRYPT_KEY_HANDLE,
    hexportkey: BCRYPT_KEY_HANDLE,
    pszblobtype: PCWSTR,
    pboutput: *mut u8,
    cboutput: u32,
    pcbresult: *mut u32,
    dwflags: u32,
) -> NTSTATUS {
    let hook_lock = HOOK_CRYPT_EXPORT.read().unwrap_window();
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

extern "system" fn open_stub(
    phalgorithm: *mut BCRYPT_ALG_HANDLE,
    pszalgid: PCWSTR,
    pszimplementation: PCWSTR,
    dwflags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
) -> NTSTATUS {
    let mut keys = SEGARSAKEYS.write().unwrap_window();
    if keys.len() == 0 {
        if let Some(x) = get_rsa_key().unwrap_window() {
            *keys = x;
        }
    };
    let hook_lock = HOOK_OPEN.read().unwrap_window();
    hook_lock
        .as_ref()
        .unwrap()
        .call(phalgorithm, pszalgid, pszimplementation, dwflags)
}

extern "system" fn getaddrinfo_stub(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    let settings_lock = SETTINGS.read().unwrap_window();
    let settings = settings_lock.as_ref().unwrap_window();
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
                .unwrap()
                .as_mut()
                .unwrap()
                .disable()
                .unwrap_window()
        };
        if let Ok(mut socket) = TcpStream::connect((addr_in.as_str(), 11000)) {
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).unwrap_window();
            let len = u32::from_le_bytes(len);
            let mut data = vec![0u8; len as usize];
            socket.read_exact(&mut data).unwrap_window();
            let keys = rmp_serde::from_slice::<Vec<Keys>>(&data).unwrap_window();
            *SHIPRSAKEYS.write().unwrap_window() = keys;
        }
        unsafe {
            HOOK_GETADDRINFO
                .write()
                .unwrap()
                .as_mut()
                .unwrap()
                .enable()
                .unwrap_window()
        };
    }
    if let Ok(addr) = addr_in.parse::<Ipv4Addr>() {
        let lock = SHIPRSAKEYS.read().unwrap_window();
        let key = lock.iter().find(|k| k.ip == addr);
        if let Some(key) = key {
            *USERRSAKEYS.write().unwrap_window() = key.key.clone();
        }
    }
    let addr_in = CString::new(addr_in).unwrap_window();
    let hook_lock = HOOK_GETADDRINFO.read().unwrap_window();
    hook_lock.as_ref().unwrap().call(
        PCSTR::from_raw(addr_in.as_ptr() as *const u8),
        pservicename,
        phints,
        ppresult,
    )
}

fn load_fn(dll_name: &str, fn_name: &str) -> Result<FARPROC, io::Error> {
    unsafe {
        let dll_name_u16: Vec<u16> = dll_name.encode_utf16().chain(0..=0).collect();
        let fn_name_u8: Vec<u8> = fn_name.bytes().chain(0..=0).collect();

        let handle = LoadLibraryW(PCWSTR::from_raw(dll_name_u16.as_ptr()))?;
        HANDLES.lock().unwrap().push(handle);
        Ok(GetProcAddress(handle, PCSTR::from_raw(fn_name_u8.as_ptr())))
    }
}

fn create_hook<T: Function>(orig_fn: T, new_fn: T) -> Result<GenericDetour<T>, Box<dyn Error>> {
    unsafe {
        let hooked_fn = GenericDetour::<T>::new(orig_fn, new_fn)?;
        hooked_fn.enable()?;
        Ok(hooked_fn)
    }
}

fn get_rsa_key() -> Result<Option<Vec<Vec<u8>>>, windows::core::Error> {
    let settings_lock = SETTINGS.read().unwrap_window();
    let settings = settings_lock.as_ref().unwrap_window();
    let pid = get_process("pso2.exe")?.unwrap();
    let Some(data) = get_module(pid, "pso2.exe")? else {
        return Ok(None);
    };
    let mut keys: Vec<Vec<u8>> = vec![];
    let mut data_iter = data.iter();
    let mut key_num = 1;
    while data_iter.any(|&x| x == RSAHEADER[0]) {
        let tmp_iter = data_iter.by_ref().take(11);
        if tmp_iter
            .zip(RSAHEADER.into_iter().skip(1))
            .filter(|x| *x.0 == x.1)
            .count()
            == 11
        {
            //https://learn.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
            let key_len_buff: Vec<u8> = data_iter.by_ref().take(4).copied().collect();
            let key_len = u32::from_le_bytes(key_len_buff.clone().try_into().unwrap_window());
            let key: Vec<u8> = RSAHEADER
                .into_iter()
                .chain(key_len_buff)
                .chain(data_iter.by_ref().take((key_len / 8) as usize + 4).copied())
                .collect();
            if settings.grab_keys {
                let path = PATH
                    .read()
                    .unwrap_window()
                    .as_ref()
                    .unwrap_window()
                    .join(format!("SEGAKey{key_num}.blob"));
                File::create(path)
                    .unwrap_window()
                    .write_all(&key)
                    .unwrap_window();
            }
            key_num += 1;
            keys.push(key.into_iter().collect());
        }
    }

    Ok(Some(keys))
}

fn get_base_dir(process_name: &str) -> Result<Option<String>, windows::core::Error> {
    let Some(pid) = get_process(process_name)? else {
        return Ok(None);
    };
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        if module.module_name == process_name {
            let exe_path = std::path::PathBuf::from(module.module_path);
            let dir = exe_path
                .parent()
                .unwrap_window()
                .to_string_lossy()
                .to_string();
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

fn get_process(process_name: &str) -> Result<Option<u32>, windows::core::Error> {
    let processes = ProcessSnapshot::new()?;
    for process in processes {
        if process.process_name == process_name {
            return Ok(Some(process.pid));
        }
    }
    Ok(None)
}

fn get_module(pid: u32, module_name: &str) -> Result<Option<&mut [u8]>, windows::core::Error> {
    let modules = ModuleSnapshot::new(pid)?;
    for module in modules {
        if module.module_name == module_name {
            return Ok(Some(unsafe { module.get_memory_mut() }));
        }
    }
    Ok(None)
}

fn check_ngs() -> bool {
    let mut path = PATH.read().unwrap_window().clone().unwrap_window();
    match fs::metadata(path.join("pso2_bin")) {
        Ok(x) if x.is_dir() => path.push("pso2_bin"),
        Ok(_) | Err(_) => {}
    };
    path.push("pso2reboot.dll");
    if fs::metadata(path).is_ok() {
        return true;
    }
    false
}

#[ctor::dtor]
fn shutdown() {
    let mut handles = HANDLES.lock().unwrap();
    for handle in handles.drain(..) {
        let _ = unsafe { FreeLibrary(handle) };
    }
}
