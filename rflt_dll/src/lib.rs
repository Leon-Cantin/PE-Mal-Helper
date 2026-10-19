#![no_std]
#![no_main]

use core::{
    ffi::{CStr, c_void},
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::{HANDLE, HINSTANCE},
    System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_CHARACTERISTICS}, Memory::{PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtect}, SystemServices::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
        }
    },
    UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxA},
};

fn payload_function() {
    unsafe {
        MessageBoxA(
            null_mut(),
            b"Hello from reflective DLL!\0".as_ptr(),
            b"Hello\0".as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            payload_function();
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        DLL_PROCESS_DETACH => {}
        _ => {}
    }

    return true;
}

fn get_base_addr() -> *mut c_void {
    let addr = reflect_entry as *mut u8;
    for i in (0..0x10000).step_by(4) {
        unsafe {
            let dos_header = addr.byte_offset(-i) as *mut IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                continue;
            }
            let nt_header =
                dos_header.byte_add((*dos_header).e_lfanew as _) as *mut IMAGE_NT_HEADERS64;
            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                continue;
            }

            return dos_header as _;
        }
    }

    return 0 as _;
}

const IMAGE_SCN_MEM_READWRITE: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
const IMAGE_SCN_MEM_EXECUTEWRITE: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
const IMAGE_SCN_MEM_EXECUTEREAD: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
const IMAGE_SCN_MEM_EXECUTEREADWRITE: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
pub fn set_sections_permissions(image: *mut c_void) {
    unsafe {
        let dos_hdr = image as *const IMAGE_DOS_HEADER;
        let nt_hdr = image.byte_add((*dos_hdr).e_lfanew as _) as *const IMAGE_NT_HEADERS64;

        for section in pe_parser::SectionIter::from_nt_hdr(nt_hdr) {
            //Keep only the flags we care about
            let mem_charac = (*section).Characteristics & IMAGE_SCN_MEM_EXECUTEREADWRITE;
            let protection = match mem_charac {
                IMAGE_SCN_MEM_WRITE => PAGE_WRITECOPY,
                IMAGE_SCN_MEM_READ => PAGE_READWRITE, //Cheating here so we can resolve the IAT
                IMAGE_SCN_MEM_READWRITE => PAGE_READWRITE,
                IMAGE_SCN_MEM_EXECUTE => PAGE_EXECUTE,
                IMAGE_SCN_MEM_EXECUTEWRITE => PAGE_EXECUTE_WRITECOPY,
                IMAGE_SCN_MEM_EXECUTEREAD => PAGE_EXECUTE_READ,
                IMAGE_SCN_MEM_EXECUTEREADWRITE => PAGE_EXECUTE_READWRITE,
                _ => {
                    unimplemented!()
                }
            };

            let mut old_prot = 0;
            let mut addr = image.byte_add((*section).VirtualAddress as _);
            let mut byte_count = (*section).SizeOfRawData as usize;
            let success = nt_impl::NtProtectVirtualMemory(
                -1isize as HANDLE,
                &mut addr,
                &mut byte_count,
                protection,
                &mut old_prot,
            );
            if success < 0 {
                panic!();
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn reflect_entry( image: *mut c_void ) {
    unsafe{
        //let image = get_base_addr();
        //Set protection first and leave "read only" as "read/write" for IAT resolution
        //set_sections_permissions(image);
        pe_mapper::fix_iat(image);
        pe_mapper::set_sections_permissions(image);
        pe_mapper::tls_callbacks(image);
        pe_mapper::set_exceptions(image);
        payload_function();
        //DllMain(image, DLL_PROCESS_ATTACH, image as _);
    }
}