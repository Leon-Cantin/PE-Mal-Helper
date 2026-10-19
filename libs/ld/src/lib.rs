use std::cmp::min;
use std::mem::offset_of;
use std::{ffi::c_void, ptr::null_mut};

use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use strobf::{Djb2, obf_format_error, obf_println_info};
use widestring::WideCStr;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
};

pub mod iat;
pub mod ld_syscall;
pub mod ssn;

fn get_peb() -> *const PEB{
    unsafe{
        #[cfg(target_pointer_width = "64")]
        {
            use std::arch::asm;

            let gs: u64;
            asm!("mov {}, gs:0x60", out(reg) gs);
            gs as *const PEB
        }
        
        #[cfg(target_pointer_width = "32")]
        {
            let fs: u32;
            asm!("mov {}, fs:0x30", out(reg) fs);
            fs as *const PEB
        }
    }
}

pub fn get_module_handle_str(api_name: &str) -> *mut c_void {
    let raw_obf = strobf::Raw::new(api_name);
    get_module_handle( &raw_obf)
}

pub fn get_module_handle<T: strobf::TStrObf<T>>(api_name: &T) -> *mut c_void {
    unsafe {
        let ppeb = get_peb();

        let ldr = (*ppeb).Ldr;
        let list_head = (&(*ldr).InMemoryOrderModuleList)
            as *const ntapi::winapi::shared::ntdef::LIST_ENTRY
            as *const LIST_ENTRY;
        let mut list_entry = (*list_head).Flink;

        let offset = offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        while list_entry != list_head as *mut LIST_ENTRY {
            let dte: *mut LDR_DATA_TABLE_ENTRY = (list_entry as *mut u8).sub(offset) as *mut LDR_DATA_TABLE_ENTRY;
            let base_dll_name = &((*dte).BaseDllName);

            if !base_dll_name.Buffer.is_null() && base_dll_name.Length != 0 {
                let wstr = WideCStr::from_ptr_unchecked(
                    base_dll_name.Buffer,
                    (base_dll_name.Length / 2) as usize,
                );
                if api_name.eq_wcstr(wstr) {
                    return (*dte).DllBase as *mut c_void;
                }
            }

            list_entry = (*list_entry).Flink;
        }
    }

    null_mut()
}

fn make_cstr( dst:&mut [u8],src: &[u8], len:usize ){
    let max_copy = min(dst.len(), src.len());
    assert!( (len+1) <= max_copy );
    for i in 0 .. len{
        dst[i] = src[i];
    }
    dst[len] = 0;
}

fn resolve_forwarded_function(fwd:&str)-> Result<*mut c_void, String>{
    unsafe{
        let mut cmod_name = [0u8;0x100];
        let Some(dot_pos) = fwd.as_bytes().iter().position(|&b| b == b'.') else {
            return Err( obf_format_error!("[!]ld::resolve_forwarded_function Couldn't find '.' in: {:#?}", fwd ));};
        make_cstr( &mut cmod_name, fwd.as_bytes(), dot_pos );
        let fn_name = &fwd[dot_pos+1..];

        //TODO: Remove this for our own implementation
        //TODO: Utiliser LdrLoadDll qui vient de ntdll.dll à la place
        let loaded_lib = ld_load_library_a(cmod_name.as_ptr() as _);
        if loaded_lib.is_null(){
            return Err( obf_format_error!("[!]ld::resolve_forwarded_function Couldn't find module: {:#?}", cmod_name ));}

        if fn_name.as_bytes()[0] == b'#' {
            unimplemented!("NOT YET TESTED, TEST ME FIRST THEN REMOVE THIS LINE");
            let mut ordinal:u16 = 0;
            let chr_nbr = &fn_name.as_bytes()[1..];
            for c in chr_nbr {
                if *c == 0 || *c < 48 || *c > 57 {
                    break;
                }
                ordinal = ordinal * 10 + (*c - 48) as u16;
            };
            return Ok(get_proc_addr_by_ordinal(loaded_lib, ordinal))
        }
        else{
            let obf_func_name = Djb2::new(fn_name);
            return Ok(get_proc_addr(loaded_lib, &obf_func_name));
        }
    }
}

pub fn get_proc_addr_str(h_module: *mut c_void, api_name: &str) -> *mut c_void {
    let raw_obf = strobf::Raw::new(api_name);
    get_proc_addr(h_module, &raw_obf)
}

pub fn strlen( ptr:*const u8) -> usize{
    let mut len = 0;

    // SAFETY: Outer caller has provided a pointer to a valid C string.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }

    len
}

pub fn get_proc_addr<T: strobf::TStrObf<T>>(h_module: *mut c_void, api_name: &T) -> *mut c_void {
    unsafe {
        let p_base = h_module as *mut i8;
        // get the dos header and doing the check !
        let p_img_dos_hdr = p_base as *const IMAGE_DOS_HEADER;
        let p_img_nt_hdrs =
            (p_base.wrapping_add((*p_img_dos_hdr).e_lfanew as usize)) as *const IMAGE_NT_HEADERS64;

        let img_opt_hdr = &(*p_img_nt_hdrs).OptionalHeader;

        let img_data_dir = &img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let p_img_export_dir = p_base.wrapping_add(img_data_dir.VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let function_name_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfNames as usize)) as *const u32;
        let function_address_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfFunctions as usize)) as *const u32;
        let function_ordinal_array =
            (p_base.wrapping_add((*p_img_export_dir).AddressOfNameOrdinals as usize)) as *const u16;

        for i in 0..(*p_img_export_dir).NumberOfNames {
            let p_function_name =
                p_base.wrapping_add(*function_name_array.offset(i as isize) as usize) as *const i8;
            let func_name_len = strlen(p_function_name as _);
            let function_name = str::from_utf8_unchecked(std::slice::from_raw_parts(p_function_name as _, func_name_len));

            if api_name.eq_str(function_name) {
                let ordinal = *function_ordinal_array.offset(i as isize);
                let func_offset = *function_address_array.offset(ordinal as isize) as usize;
                let p_function = p_base.wrapping_add(func_offset) as *mut c_void;
                obf_println_info!(
                    "[ld] [{}] Function Name: {:?} - {:?} - Ordinal: {}",
                    i, function_name, p_function, ordinal
                );
                if (p_img_export_dir as usize <= p_function as usize) && ((p_function as usize )< p_img_export_dir.byte_add(img_data_dir.Size as usize) as usize){
                    let fn_name_len = strlen(p_function as _);
                    let fn_name = str::from_utf8_unchecked(std::slice::from_raw_parts(p_function as _, fn_name_len));
                    obf_println_info!( "[ld] Forwarded function: {:#?}", fn_name );
                    match resolve_forwarded_function(fn_name){
                        Err(e) => {
                            panic!("{}", e);
                        }
                        Ok(e) => {
                            obf_println_info!("[ld] Found fowarded func at {:?}", e);
                            return e;
                        }
                    }
                }else{
                    return p_function;
                }

            }
        }
        return null_mut();
    }
}

pub fn get_proc_addr_by_ordinal(h_module: *mut c_void, ordinal:u16) -> *mut c_void {
    unsafe {
        let p_base = h_module as *mut i8;
        let p_img_dos_hdr = p_base as *const IMAGE_DOS_HEADER;
        let p_img_nt_hdrs =
            (p_base.byte_add((*p_img_dos_hdr).e_lfanew as usize)) as *const IMAGE_NT_HEADERS64;

        let img_opt_hdr = &(*p_img_nt_hdrs).OptionalHeader;

        let img_data_dir = &img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let p_img_export_dir = p_base.byte_add(img_data_dir.VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

        let function_address_array =
            (p_base.byte_add((*p_img_export_dir).AddressOfFunctions as usize)) as *const u32;

        let fn_rva = *function_address_array.offset(ordinal as isize) as usize;
        let p_function = p_base.byte_add(fn_rva) as *mut c_void;
        //If ordinal points to the import dir, then we must resolve a forwarded function
        if (p_img_export_dir as usize <= p_function as usize) && ((p_function as usize )< p_img_export_dir.byte_add(img_data_dir.Size as usize) as usize){
            let fn_name_len = strlen(p_function as _);
            let fn_name = str::from_utf8_unchecked(std::slice::from_raw_parts(p_function as _, fn_name_len));
            obf_println_info!( "[ld] Found Forwarded function name: {:#?} - addr:{:?} - Ordinal: {}", fn_name, p_function, ordinal );
            match resolve_forwarded_function(fn_name){
                Err(e) => {
                    panic!("{}", e );
                }
                Ok(e) => {
                    obf_println_info!("[ld] Found fowarded func at {:?}", e);
                    return e;
                }
            }
        }else{
            obf_println_info!(
                "[ld] Found Ordinal Function: {:?} - addr:{:?}",
                ordinal,p_function
            );
            return p_function;
        }
    }
}

const OBF_K32_DLL: strobf::TObf = strobf::TObf::new("KERNEL32.DLL");
const OBF_LOAD_LIBRARY_A: strobf::TObf = strobf::TObf::new("LoadLibraryA");
ld_register!(
    OBF_LOAD_LIBRARY_A,
    OBF_K32_DLL,
    ld_load_library_a
);
unsafe extern "C" {
    pub fn ld_load_library_a(
        lp_lib_file_name : *const u8
    ) -> HMODULE;
}