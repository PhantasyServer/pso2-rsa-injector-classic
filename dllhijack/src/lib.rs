use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{BOOL, HINSTANCE, HWND},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW},
            SystemServices::DLL_PROCESS_ATTACH,
        },
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};
#[no_mangle]
extern "system" fn DllMain(_: HINSTANCE, fdw_reason: u32, _: *mut ()) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        let dll_name = "rsa_inject.dll";
        let cryptbase_path: Vec<_> = dll_name.encode_utf16().chain([0]).collect();
        if let Ok(_) = unsafe { GetModuleHandleW(PCWSTR::from_raw(cryptbase_path.as_ptr())) } {
            return false.into();
        }
        // UNSAFETY: Calling LoadLibrary in DllMain is prohibited.
        let module = match unsafe { LoadLibraryW(PCWSTR::from_raw(cryptbase_path.as_ptr())) } {
            Ok(m) => m,
            Err(e) => {
                print_msgbox(&format!("{e}"), "LoadLibrary error");
                return false.into();
            }
        };
        let init_str = "init\0";
        let init_fn = unsafe { GetProcAddress(module, PCSTR::from_raw(init_str.as_ptr())) };
        // UNSAFETY: Synchronization is prohibited. (I think mutexes count)
        match init_fn {
            Some(f) => unsafe { std::mem::transmute::<_, extern "system" fn()>(f)() },
            None => {}
        };
    }
    false.into()
}

fn print_msgbox(msg: &str, header: &str) {
    let msg_utf16: Vec<_> = msg.encode_utf16().chain([0]).collect();
    let header_utf16: Vec<_> = header.encode_utf16().chain([0]).collect();
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR::from_raw(msg_utf16.as_ptr()),
            PCWSTR::from_raw(header_utf16.as_ptr()),
            MB_OK | MB_ICONERROR,
        )
    };
}
