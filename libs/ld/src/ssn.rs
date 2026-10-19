use std::{ffi::c_void};

//Might be overkill to obfuscate syscall, ret and mov bytes

const KEY:u8 = 0xAB;
const MOV_EAX_BYTE1:u8 = 0xB8;
const OBF_MOV_EAX_BYTE1:u8 = MOV_EAX_BYTE1 ^ KEY;
const NT_FN_SIZE:isize = 0x20;
pub fn find( fn_addr:*const c_void, search_range:usize ) -> Option<u32>{
    unsafe{
        let mov_addr = fn_addr.byte_offset(3) as *const u8;
        for i in 0 .. search_range as isize{
            //Check forward
            if *(mov_addr.byte_offset(NT_FN_SIZE*i) as *const u8) ^ KEY == OBF_MOV_EAX_BYTE1{
                return Some(*(mov_addr.byte_offset(NT_FN_SIZE*i + 1) as *const u32) - i as u32 )
            }
            //Check Backward
            if *(mov_addr.byte_offset(NT_FN_SIZE*-i) as *const u8) ^ KEY == OBF_MOV_EAX_BYTE1{
                return Some(*(mov_addr.byte_offset(NT_FN_SIZE*-i + 1) as *const u32) + i as u32 )
            }
        }
        return None;
    }
}

const SYSCALL_BYTE1:u8 = 0x0F;
const SYSCALL_BYTE2:u8 = 0x05;
const RET_BYTE1:u8 = 0xC3;
const OBF_SYSCALL_BYTE1:u8 = SYSCALL_BYTE1 ^ KEY;
const OBF_SYSCALL_BYTE2:u8 = SYSCALL_BYTE2 ^ KEY;
const OBF_RET_BYTE1:u8 = RET_BYTE1 ^ KEY;

pub fn find_syscall( fn_addr:*const c_void, search_range:usize ) -> Option<usize>{
    unsafe{
        let syscall_addr = fn_addr.byte_offset(5) as *const u8;
        for i in 0..search_range as isize{
            if *syscall_addr.byte_offset(i) ^ KEY == OBF_SYSCALL_BYTE1 
                && *syscall_addr.byte_offset(i+1) ^ KEY == OBF_SYSCALL_BYTE2
                && *syscall_addr.byte_offset(i+2) ^ KEY == OBF_RET_BYTE1{
                    return Some(syscall_addr.byte_offset(i) as _);
                }
            if *syscall_addr.byte_offset(-i) ^ KEY == OBF_SYSCALL_BYTE1 
                && *syscall_addr.byte_offset(-i+1) ^ KEY == OBF_SYSCALL_BYTE2
                && *syscall_addr.byte_offset(-i+2) ^ KEY == OBF_RET_BYTE1{
                    return Some(syscall_addr.byte_offset(-i) as _);
                }
        }

        return None;
    }
}