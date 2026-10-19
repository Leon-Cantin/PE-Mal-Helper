use std::{
    ffi::{CStr, CString, c_void},
    mem::offset_of,
    path::Path,
    ptr::{null, null_mut},
};

use strobf::{Djb2, obf_println_debug, obf_println_error, obf_println_info};
use strobf::{obf_format_error,obf_panic};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, INVALID_SET_FILE_POINTER, OPEN_EXISTING,
        ReadFile, SetFilePointer,
    },
    System::{
        Diagnostics::Debug::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64,
            IMAGE_RUNTIME_FUNCTION_ENTRY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
            IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_CHARACTERISTICS, IMAGE_SECTION_HEADER,
            RtlAddFunctionTable,
        },
        Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY, VirtualAlloc,
        },
        SystemServices::{
            DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
            IMAGE_IMPORT_BY_NAME, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64,
            IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
            IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, IMAGE_TLS_DIRECTORY64,
        },
    },
};

pub fn map_for_execution(pe_path: &Path) -> Result<*mut c_void, String> {
    let (pe, _pe_size) = match map_pe(pe_path, PAGE_READWRITE) {
        Err(e) => {
            return Err(obf_format_error!("Mapping of PE failed with: {}", e));
        }
        Ok(pe) => pe,
    };

    fix_reloc(pe);
    if let Err(e) = fix_iat(pe) {
        return Err(obf_format_error!("IAT fixing failed with: {}", e));
    }

    set_sections_permissions(pe);

    tls_callbacks(pe);

    if let Err(e) = set_exceptions(pe) {
        return Err(obf_format_error!("Set exception failed with: {}", e));
    }

    return Ok(pe);
}

pub fn tls_callbacks(image: *mut c_void) {
    unsafe {
        let dos_hdr = image as *const IMAGE_DOS_HEADER;
        let nt_hdr = image.byte_add((*dos_hdr).e_lfanew as _) as *const IMAGE_NT_HEADERS64;
        let img_tls_dir_entry =
            &(*nt_hdr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
        let tls_dir =
            image.byte_add(img_tls_dir_entry.VirtualAddress as _) as *const IMAGE_TLS_DIRECTORY64;
        let mut current_callback = (*tls_dir).AddressOfCallBacks as *const usize;
        while *current_callback as usize != 0 {
            let callback: unsafe extern "system" fn(*const c_void, u32, *const c_void) =
                std::mem::transmute(*current_callback);
            callback(image, DLL_PROCESS_ATTACH, null());
            current_callback = current_callback.add(1);
        }
    }
}

pub fn set_exceptions(image: *mut c_void) -> Result<(), String> {
    unsafe {
        let dos_hdr = image as *const IMAGE_DOS_HEADER;
        let nt_hdr = image.byte_add((*dos_hdr).e_lfanew as _) as *const IMAGE_NT_HEADERS64;
        let exception_dir_entry =
            &(*nt_hdr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
        if exception_dir_entry.Size == 0 {
            return Ok(());
        }
        let exception_dir = image.byte_add(exception_dir_entry.VirtualAddress as _)
            as *const IMAGE_RUNTIME_FUNCTION_ENTRY;
        if !RtlAddFunctionTable(
            exception_dir,
            exception_dir_entry.Size / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>() as u32,
            image as _,
        ) {
            return Err(obf_format_error!("RtlAddFunctionTable failed for exceptions"));
        }
        obf_println_info!("[+]Exceptions handlers added");
        return Ok(());
    }
}

pub fn read_file_at(
    h_file: *mut c_void,
    dst: *mut c_void,
    offset: i32,
    len: usize,
) -> Result<(), String> {
    unsafe {
        let result = SetFilePointer(h_file, offset, null_mut(), FILE_BEGIN);
        if result == INVALID_SET_FILE_POINTER {
            return Err(obf_format_error!(
                "SetFilePointer err:0x{:08X} for offset:0x{:x}",
                GetLastError(),
                offset
            ));
        }

        let mut nb_bytes_read = 0;
        let success = ReadFile(h_file, dst as _, len as _, &mut nb_bytes_read, null_mut());

        if success == 0 || nb_bytes_read as usize != len {
            return Err(obf_format_error!("ReadFile err:0x{:08X}", GetLastError(),));
        }

        Ok(())
    }
}

pub fn load_pe_header(h_file_pe: *mut c_void) -> Result<Vec<u8>, String> {
    let nt_header_offset_offset = offset_of!(IMAGE_DOS_HEADER, e_lfanew);
    type TLfanew = i32;
    let mut nt_header_offset: TLfanew = 0;
    let p_nt_header_offset: *mut TLfanew = &mut nt_header_offset;

    if let Err(e) = read_file_at(
        h_file_pe,
        p_nt_header_offset as _,
        nt_header_offset_offset as _,
        size_of::<TLfanew>(),
    ) {
        return Err(obf_format_error!(
            "Error while reading file DOS header e_lfanew: {}",
            e
        ));
    }

    let nb_sections_offset = nt_header_offset as usize
        + offset_of!(IMAGE_NT_HEADERS64, FileHeader)
        + offset_of!(IMAGE_FILE_HEADER, NumberOfSections);
    type TNbsections = u16;
    let mut nb_sections: TNbsections = 0;
    let p_nb_sections: *mut TNbsections = &mut nb_sections;

    if let Err(e) = read_file_at(
        h_file_pe,
        p_nb_sections as _,
        nb_sections_offset as _,
        size_of::<TNbsections>(),
    ) {
        return Err(obf_format_error!(
            "Error while reading file NT header header NumberOfSections: {}",
            e
        ));
    }

    let header_size = nt_header_offset as usize
        + size_of::<IMAGE_NT_HEADERS64>()
        + size_of::<IMAGE_SECTION_HEADER>() * nb_sections as usize;
    let mut mem = vec![0u8; header_size];
    if let Err(e) = read_file_at(h_file_pe, mem.as_mut_ptr() as _, 0, header_size) {
        return Err(obf_format_error!("Error while reading file Header: {}", e));
    }

    return Ok(mem);
}

pub fn map_pe(
    pe_path: &Path,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<(*mut c_void, usize), String> {
    unsafe {
        let path = CString::new(pe_path.to_str().unwrap()).unwrap();
        let h_file = CreateFileA(
            path.as_ptr() as _,
            GENERIC_READ,
            0x00,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );
        if h_file == INVALID_HANDLE_VALUE {
            return Err(obf_format_error!(
                "Error 0x{:08X} while creating file for {}",
                GetLastError(),
                pe_path.to_string_lossy()
            ));
        }

        let header = match load_pe_header(h_file) {
            Err(e) => {
                CloseHandle(h_file);
                return Err(obf_format_error!("{} for {}", e, pe_path.to_string_lossy(),));
            }
            Ok(h) => h,
        };

        let header_base = header.as_ptr();
        let dos_hdr = header_base as *const IMAGE_DOS_HEADER;
        if (*dos_hdr).e_magic != IMAGE_DOS_SIGNATURE {
            CloseHandle(h_file);
            return Err(obf_format_error!("Not a DOS image"));
        }

        let nt_hdr = header_base.byte_add((*dos_hdr).e_lfanew as _) as *const IMAGE_NT_HEADERS64;
        if (*nt_hdr).Signature != IMAGE_NT_SIGNATURE {
            CloseHandle(h_file);
            return Err(obf_format_error!("Not a NT image"));
        }

        let va_size = (*nt_hdr).OptionalHeader.SizeOfImage;
        let mapped_pe = VirtualAlloc(null(), va_size as _, MEM_RESERVE | MEM_COMMIT, protection);
        if mapped_pe == null_mut() {
            CloseHandle(h_file);
            return Err(obf_format_error!(
                "Error 0x{:08X} while allocating virtual mem for {}",
                GetLastError(),
                pe_path.to_string_lossy()
            ));
        }

        //Header Mapping
        std::ptr::copy_nonoverlapping(header_base, mapped_pe as _, header.len());
        //Sections Mapping
        for section in pe_parser::SectionIter::from_nt_hdr(nt_hdr) {
            obf_println_info!(
                "[+] Copying section {}: src=0x{:x}, dst=0x{:x}, size=0x{:x}",
                CStr::from_bytes_until_nul(&(*section).Name)
                    .unwrap()
                    .to_string_lossy(),
                (*section).PointerToRawData,
                (*section).VirtualAddress,
                (*section).SizeOfRawData
            );
            if let Err(e) = read_file_at(
                h_file,
                mapped_pe.byte_add((*section).VirtualAddress as _),
                (*section).PointerToRawData as _,
                (*section).SizeOfRawData as _,
            ) {
                CloseHandle(h_file);
                return Err(obf_format_error!("Error while copying section: {e}"));
            }
        }

        CloseHandle(h_file);
        obf_println_info!("Mapped PE as 0x{:08X}", mapped_pe as usize);

        Ok((mapped_pe, va_size as _))
    }
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
            obf_println_debug!(
                "[+] Changing protection on section {} to 0x{:x}",
                CStr::from_bytes_until_nul(&(*section).Name)
                    .unwrap()
                    .to_string_lossy(),
                (*section).Characteristics
            );
            //Keep only the flags we care about
            let mem_charac = (*section).Characteristics & IMAGE_SCN_MEM_EXECUTEREADWRITE;
            let protection = match mem_charac {
                IMAGE_SCN_MEM_WRITE => PAGE_WRITECOPY,
                IMAGE_SCN_MEM_READ => PAGE_READONLY,
                IMAGE_SCN_MEM_READWRITE => PAGE_READWRITE,
                IMAGE_SCN_MEM_EXECUTE => PAGE_EXECUTE,
                IMAGE_SCN_MEM_EXECUTEWRITE => PAGE_EXECUTE_WRITECOPY,
                IMAGE_SCN_MEM_EXECUTEREAD => PAGE_EXECUTE_READ,
                IMAGE_SCN_MEM_EXECUTEREADWRITE => PAGE_EXECUTE_READWRITE,
                _ => {
                    obf_panic!(
                        "[!] Unimplemented page protection 0x{:08X} for section {}",
                        (*section).Characteristics,
                        CStr::from_bytes_until_nul(&(*section).Name)
                            .unwrap()
                            .to_string_lossy()
                    )
                }
            };

            let mut old_prot = 0;
            let mut base_addr = image.byte_add((*section).VirtualAddress as _);
            let mut size = (*section).SizeOfRawData as usize;
            let success = nt_impl::NtProtectVirtualMemory(
                -1isize as HANDLE,
                &mut base_addr,
                &mut size,
                protection,
                &mut old_prot,
            );
            if success == 0 {
                obf_println_error!(
                    "Failed to change protection for section {}",
                    CStr::from_bytes_until_nul(&(*section).Name)
                        .unwrap()
                        .to_string_lossy()
                );
            }
        }
    }
}

pub fn fix_iat(image: *mut c_void) -> Result<(), String> {
    unsafe {
        for import_desc in pe_parser::ImportIter::from_image(image) {
            let int_rva = (*import_desc).Anonymous.OriginalFirstThunk;
            let iat_rva = (*import_desc).FirstThunk;
            let dll_name = image.byte_add((*import_desc).Name as _) as * const u8;
            let _dll_name_str = str::from_utf8_unchecked(std::slice::from_raw_parts(dll_name, ld::strlen(dll_name)));
            //Should be loaded in Kernel32.dll of any process
            //TODO: Use LdrLoadDll from ntdll.dll instead
            let h_module = ld::ld_load_library_a(dll_name);
            if h_module.is_null() {
                return Err(obf_format_error!(
                    "Error 0x{:08X} while loading module {}",
                    GetLastError(),
                    _dll_name_str
                ));
            }
            obf_println_info!("[+] Loaded module {}", _dll_name_str);

            let int = image.byte_add(int_rva as _) as *const u64;
            let iat = image.byte_add(iat_rva as _) as *mut u64;
            let mut i = 0;
            loop {
                let value = *int.add(i);
                if value == 0 {
                    break;
                }

                let use_ordinal = (value & IMAGE_ORDINAL_FLAG64) != 0;
                let proc_addr = if use_ordinal {
                    let ordinal = (value & 0xFFFF) as u16;
                    obf_println_debug!("reference by ordinal {}", ordinal);
                    ld::get_proc_addr_by_ordinal(h_module,ordinal)
                } else {
                    let fn_rva = value & 0x7FFFFFFF;
                    let name_entry = image.byte_add(fn_rva as _) as *const IMAGE_IMPORT_BY_NAME;
                    let fn_name: *const u8 = std::mem::transmute(&(*name_entry).Name);
                    let fn_name_str = str::from_utf8_unchecked(std::slice::from_raw_parts(fn_name, ld::strlen(fn_name)));
                    obf_println_debug!(
                        "[*] Importing {}.{}",
                        _dll_name_str,
                        fn_name_str
                    );
                    let obj_str = Djb2::new(fn_name_str);
                    ld::get_proc_addr(h_module, &obj_str) 
                };
                if proc_addr.is_null() {
                    obf_panic!("[!]fn not found");
                } else {
                    *iat.add(i) = proc_addr as _;
                    obf_println_debug!("@: 0x{:08X}", *iat);                                        
                }
                i += 1;
            }
        }
    }
    Ok(())
}

pub fn fix_reloc(image: *mut c_void) {
    fix_reloc_from(image, image);
}

pub fn fix_reloc_from(image: *mut c_void, from_addr: *mut c_void) {
    unsafe {
        let dos_hdr = image as *const IMAGE_DOS_HEADER;
        let nt_hdr = (image.byte_add((*dos_hdr).e_lfanew as usize)) as *const IMAGE_NT_HEADERS64;
        //rellocation
        let reloc_data_dir =
            &(*nt_hdr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        let mut current_block =
            image.byte_add(reloc_data_dir.VirtualAddress as _) as *const IMAGE_BASE_RELOCATION;
        let reloc_table_end = current_block.byte_add(reloc_data_dir.Size as _);

        let delta = from_addr as usize - (*nt_hdr).OptionalHeader.ImageBase as usize;
        while current_block < reloc_table_end {
            let block_end = current_block.byte_add((*current_block).SizeOfBlock as _);
            let block_va = image.byte_add((*current_block).VirtualAddress as _);
            let mut current_entry = current_block.add(1) as *const u16;
            while (current_entry as *const c_void) < (block_end as _) {
                let value = *current_entry;
                let entry_offset = value & 0x0FFF;
                let etype = value >> 12;
                let entry_va = block_va.byte_add(entry_offset as _);

                match etype as u32 {
                    IMAGE_REL_BASED_DIR64 => {
                        //64 bits field
                        *(entry_va as *mut u64) += delta as u64;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        //32 bits field
                        *(entry_va as *mut u32) += delta as u32;
                    }
                    IMAGE_REL_BASED_HIGH => {
                        //high 16 bits of 32 bits
                        *(entry_va as *mut u16) += ((delta & 0xFFFF0000) >> 16) as u16;
                    }
                    IMAGE_REL_BASED_LOW => {
                        //lot 16 bits of 32 bits
                        *(entry_va as *mut u16) += (delta & 0xFFFF) as u16;
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {
                        //no relocation required
                    }
                    _ => {
                        obf_panic!("[!] unimplemented reloc type {}", etype)
                    }
                }

                current_entry = current_entry.add(1);
            }
            current_block = current_block.byte_add((*current_block).SizeOfBlock as _);
        }
    }
}
