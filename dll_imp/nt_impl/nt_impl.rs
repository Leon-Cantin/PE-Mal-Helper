use std::{os::raw::c_void, u32};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::System::Memory::SECTION_INHERIT;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, SECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE};
use windows_sys::Win32::{
        Foundation::HANDLE,
        System::Threading::{THREAD_ACCESS_RIGHTS, THREAD_CREATION_FLAGS},
    };

const OBF_NT_DLL: strobf::TObf = strobf::TObf::new("ntdll.dll");

ld::ld_register_syscall3!(
    NtQuerySystemInformation,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtQuerySystemInformation(
        si_class: windows_sys::Wdk::System::SystemInformation::SYSTEM_INFORMATION_CLASS,
        si: *mut c_void,
        si_len: usize,
        return_len: *mut usize,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtAllocateVirtualMemory,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtAllocateVirtualMemory(
        h_proc: HANDLE,
        p_base_addr: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: VIRTUAL_ALLOCATION_TYPE,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtProtectVirtualMemory,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtProtectVirtualMemory(
        h_proc: HANDLE,
        p_base_addr: *mut *mut c_void,
        p_nb_bytes: *mut usize,
        new_access_prot: u32,
        old_access_prot: *mut u32,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtWriteVirtualMemory,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtWriteVirtualMemory(
        h_proc: HANDLE,
        base_addr: *mut c_void,
        buffer: *const c_void,
        len: usize,
        written: *mut usize,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtCreateThreadEx,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtCreateThreadEx(
        ph_thread: *mut HANDLE,
        desired_access: THREAD_ACCESS_RIGHTS,
        obj_attr: *const OBJECT_ATTRIBUTES,
        h_proc: HANDLE,
        start_routine: *const c_void,
        args: *const c_void,
        creation_flags: THREAD_CREATION_FLAGS,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize,
        attrib_list: *mut c_void,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtOpenSection,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtOpenSection(
        section_handle: *mut HANDLE,
        desired_access: SECTION_FLAGS,
        obj_attr: *const OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtMapViewOfSection,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtMapViewOfSection(
        section_handle: HANDLE,
        process_handle: HANDLE,
        base_addr: *mut *mut c_void,
        zerobits: usize,
        commitsize: usize,
        sectionoffset: *mut i64,
        viewsize: *mut usize,
        inheritdisposition: SECTION_INHERIT,
        allocationtype: u32,
        win32protect: PAGE_PROTECTION_FLAGS,
    ) -> NTSTATUS;
}

ld::ld_register_syscall3!(
    NtUnmapViewOfSection,
    OBF_NT_DLL
);
unsafe extern "C" {
    pub fn NtUnmapViewOfSection(
        process_handle: HANDLE,
        base_addr: *const c_void,
    ) -> NTSTATUS;
}