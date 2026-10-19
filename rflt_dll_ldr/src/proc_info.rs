use std::{ffi::{OsString, c_void}, os::windows::ffi::OsStringExt, ptr::null_mut, slice};

use windows_sys::{Wdk::System::SystemInformation::SystemProcessInformation, Win32::{Foundation::STATUS_INFO_LENGTH_MISMATCH, System::WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION}}};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK};

struct SystemProcessInformationIter{
    p_start_si:*const SYSTEM_PROCESS_INFORMATION,
    p_next_si:Option<*const SYSTEM_PROCESS_INFORMATION>,
}

impl SystemProcessInformationIter{
    fn new(buf:&Vec<u8>)->SystemProcessInformationIter{
        SystemProcessInformationIter { 
            p_start_si:buf.as_ptr() as _ ,
            p_next_si:Some(buf.as_ptr() as _)
        }
    }
}

impl Iterator for SystemProcessInformationIter{
    type Item = *const SYSTEM_PROCESS_INFORMATION;

    fn next(&mut self)->Option<Self::Item>{
        unsafe{
            let value = self.p_next_si;
            self.p_next_si = match value{
                None=>{None},
                Some(n)=>{
                    let offset = (*n).NextEntryOffset as usize;
                    if offset == 0{
                        None
                    }
                    else{
                        Some((n as *mut u8).add( (*n).NextEntryOffset as usize ) as _)
                    }
                }
            };
            return value;
        }
    }
}

fn query_process_info_all()
-> Result<Vec<u8>,String>
{
    let mut si_size = 0;
    let status = unsafe {nt_impl::NtQuerySystemInformation(
        SystemProcessInformation,
        null_mut(), 
        0, 
        &mut si_size)} ;

    if status < 0 && status != STATUS_INFO_LENGTH_MISMATCH{
        return Err(format!("NtQuerySystemInformation failed to get the size: 0x{:08X}", status));
    }

    let si_buf = vec![0u8;si_size];

    let p_si_buf = si_buf.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

    let status = unsafe{ nt_impl::NtQuerySystemInformation(
        SystemProcessInformation, 
        p_si_buf as *mut c_void, 
        si_size, 
        &mut si_size)};

    if status < 0 {
        return Err(format!("NtQuerySystemInformation failed: 0x{:08X}", status));
    }

    return Ok(si_buf);
}

pub fn query_process_info_from_name( proc_name:&OsString ) -> Result<Vec<u8>,String>
{
    let buf = query_process_info_all()?;
    for p_si in SystemProcessInformationIter::new(&buf) {
        unsafe{
            if (*p_si).ImageName.Buffer != null_mut(){
                let other_proc_name = OsString::from_wide(
                    slice::from_raw_parts((*p_si).ImageName.Buffer, ((*p_si).ImageName.Length/2) as usize));
                
                if *proc_name == other_proc_name{
                    //Add extra size for each extra SYSTEM_THREAD_INFORMATION struct
                    let found_size = size_of::<SYSTEM_PROCESS_INFORMATION>() + size_of::<SYSTEM_THREAD_INFORMATION>() * ((*p_si).NumberOfThreads - 1) as usize;
                    let mut found_buf = vec![0u8;found_size];
                    std::ptr::copy_nonoverlapping(
                        p_si as *const u8, 
                        found_buf.as_mut_ptr() as *mut u8, 
                        found_size);
                    return Ok(found_buf)
                }
            }
        }
    }
    
    Err(format!("Not Found"))
}

pub fn query_process_info( process_id:u32 ) -> Result<Vec<u8>,String>
{
    let buf = query_process_info_all()?;
    for p_si in SystemProcessInformationIter::new(&buf) {
        unsafe{       
            if process_id == (*p_si).UniqueProcessId as u32{
                //Add extra size for each extra SYSTEM_THREAD_INFORMATION struct
                let found_size = size_of::<SYSTEM_PROCESS_INFORMATION>() + size_of::<SYSTEM_THREAD_INFORMATION>() * ((*p_si).NumberOfThreads - 1) as usize;
                let mut found_buf = vec![0u8;found_size];
                std::ptr::copy_nonoverlapping(
                    p_si as *const u8, 
                    found_buf.as_mut_ptr() as *mut u8, 
                    found_size);
                return Ok(found_buf)
            }
        }
    }
    
    Err(format!("Not Found"))
}