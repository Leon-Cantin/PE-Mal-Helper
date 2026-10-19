use std::ptr::{null_mut, write_volatile};

use strobf::{obf_panic, obf_println_info};

use crate::{get_module_handle, get_proc_addr, ssn};

#[repr(C)]
pub struct LdSyscallResolverUnit<T: strobf::TStrObf<T>> {
    pub addr: unsafe extern "C" fn(),
    pub syscall_addr: usize,
    pub ssn: u32,
    pub syscall_primer: unsafe extern "C" fn(),
    pub api_name: T,
    pub module_name: T,
}

pub struct LdSyscallGlobalResolveUnit{
    pub syscall_addr: usize
}

static mut G_LD_SYSCALL_RESOLVE_UNIT:LdSyscallGlobalResolveUnit = LdSyscallGlobalResolveUnit{ syscall_addr:0 };

pub fn set_global_syscall_addr(syscall_addr:usize){
    unsafe{ G_LD_SYSCALL_RESOLVE_UNIT.syscall_addr = syscall_addr };
}

#[macro_export]
macro_rules! ld_register_syscall {
    ($fn_name:expr, $module_name:expr, $new_fn:ident ) =>{
        paste::paste!{
        unsafe extern "C" {
            fn [<$new_fn _do_resolve>]();
            fn [<$new_fn _primer>]();
        }
        static mut [<$new_fn:upper _RU>]:$crate::ld_syscall::LdSyscallResolverUnit<strobf::TObf> = $crate::ld_syscall::LdSyscallResolverUnit{
            addr:unsafe{std::mem::transmute([<$new_fn _do_resolve>] as *const fn())},
            syscall_addr:0,
            ssn:0,
            syscall_primer:unsafe{std::mem::transmute([<$new_fn _primer>] as *const fn())},
            api_name:$fn_name,
            module_name:$module_name,
        };
        core::arch::global_asm!(
            concat!(".global ",stringify!($new_fn)),
            concat!(".global ",stringify!($new_fn),"_do_resolve"),
            concat!(".global ",stringify!($new_fn),"_primer"),
            ".section .text",
            concat!(stringify!($new_fn),":"),
            "   jmp [rip+{addr}]",                          //jmp to either do_resolve or primer
            concat!(stringify!($new_fn),"_do_resolve:"),    //jmp here before resolution
            "   lea rax, [rip+{addr}]",                     //Put the address of the structure for resoluion in RAX
            "   jmp resolve_syscall_primer",
            concat!(stringify!($new_fn),"_primer:"),        //jmp here after resolution
            "   mov eax, [rip+{addr}+{ssn_offset}]",        //ssn into EAX
            "   mov r11, [rip+{addr}+{syscall_offset}]",    //syscall instruction address, r11 isn't used in x86-64 TODO: call a function to get a random syscall
            "   mov r10, rcx",
            "   jmp r11",
            addr = sym [<$new_fn:upper _RU>],
            ssn_offset = const std::mem::offset_of!(ld::ld_syscall::LdSyscallResolverUnit<strobf::TObf>, ssn),
            syscall_offset = const std::mem::offset_of!(ld::ld_syscall::LdSyscallResolverUnit<strobf::TObf>, syscall_addr),
        );}
    }
}

#[macro_export]
macro_rules! ld_register_syscall3 {
    ($fn_name:ident, $module_name:ident ) =>{
        paste::paste!{
            const [<OBF_ $fn_name:upper>]: strobf::TObf = strobf::TObf::new(stringify!($fn_name));
            ld::ld_register_syscall!([<OBF_ $fn_name:upper>], $module_name, $fn_name);
        }
    }
}

core::arch::global_asm!(
    ".global resolve_syscall_primer",
    ".section .text",
    "resolve_syscall_primer:",
    "mov [rsp+0x08], rcx",
    "mov [rsp+0x10], rdx",
    "mov [rsp+0x18], r8",
    "mov [rsp+0x20], r9",
    "mov rcx, rax",
    "sub rsp, 0x28",
    "call {resolve}",
    "add rsp, 0x28",
    "mov rcx, [rsp+0x08]",
    "mov rdx, [rsp+0x10]",
    "mov r8, [rsp+0x18]",
    "mov r9, [rsp+0x20]",
    "jmp rax",
    resolve = sym resolve_syscall::<strobf::TObf>,
);

unsafe extern "C" fn resolve_syscall<T: strobf::TStrObf<T>>(
    id: &mut LdSyscallResolverUnit<T>,
) -> unsafe extern "C" fn() {
    let h_module = get_module_handle(&id.module_name);
    if h_module == null_mut(){
        obf_panic!("[ld_syscall] I couldn't resolve the module");
    }
    let proc_addr = get_proc_addr(h_module, &id.api_name);
    if proc_addr == null_mut() {
        obf_panic!("[ld_syscall] I couldn't resolve the function");
    } else {
        //Somewhat dangerous in multithreading but it should be fine given the order we write things.
        unsafe {
            let ssn = ssn::find(proc_addr, 256).unwrap();
            //TODO: add the posibility for random syscall addr
            let syscall_addr = if G_LD_SYSCALL_RESOLVE_UNIT.syscall_addr != 0{
                G_LD_SYSCALL_RESOLVE_UNIT.syscall_addr
            } else {
                ssn::find_syscall(proc_addr, 256).unwrap()
            };
            write_volatile(&mut id.ssn, ssn);
            write_volatile(&mut id.syscall_addr, syscall_addr);
            write_volatile(&mut id.addr, id.syscall_primer);
        }
        obf_println_info!("[ld_syscall] resolved {}::{} -> 0x{:08X}, SSN:{}, syscall_addr:0x{:08X}", id.module_name, id.api_name, proc_addr as usize, id.ssn, id.syscall_addr);
    }

    return id.addr;
}
