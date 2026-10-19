use std::ffi::c_void;

use windows_sys::Win32::{Foundation::{FILETIME, HMODULE}, System::{Diagnostics::Debug::PVECTORED_EXCEPTION_HANDLER, Threading::{
    PTP_TIMER, PTP_TIMER_CALLBACK, TP_CALLBACK_ENVIRON_V3,
}}};

const OBF_K32_DLL: strobf::TObf = strobf::TObf::new("KERNEL32.DLL");

ld::ld_register3!(
    CreateThreadpoolTimer,
    OBF_K32_DLL
);
unsafe extern "C" {
    pub fn _CreateThreadpoolTimer(
        pfnti: PTP_TIMER_CALLBACK,
        pv: *mut core::ffi::c_void,
        pcbe: *const TP_CALLBACK_ENVIRON_V3,
    ) -> PTP_TIMER;
}

ld::ld_register3!(
    SetThreadpoolTimer,
    OBF_K32_DLL
);
unsafe extern "C" {
    pub fn _SetThreadpoolTimer(
        pti : PTP_TIMER, 
        pftduetime : *const FILETIME, 
        msperiod : u32, 
        mswindowlength : u32
    );
}

ld::ld_register3!(
    LoadLibraryA,
    OBF_K32_DLL
);
unsafe extern "C" {
    pub fn _LoadLibraryA(
        lp_lib_file_name : *const u8
    ) -> HMODULE;
}

ld::ld_register3!(
    AddVectoredExceptionHandler,
    OBF_K32_DLL
);
unsafe extern "C" {
    pub fn _AddVectoredExceptionHandler(
        first : u32, 
        handler : PVECTORED_EXCEPTION_HANDLER
    ) -> *mut c_void;
}

ld::ld_register3!(
    RemoveVectoredExceptionHandler,
    OBF_K32_DLL
);
unsafe extern "C"{
    pub fn _RemoveVectoredExceptionHandler(handle : *const c_void) -> u32;
}