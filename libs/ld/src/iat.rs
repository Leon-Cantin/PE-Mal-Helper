use std::{ptr::null_mut};

use strobf::{obf_panic, obf_println_info};

use crate::{get_module_handle, get_proc_addr};

#[repr(C)]
pub struct LdResolverUnit<T: strobf::TStrObf<T>> {
    pub addr: unsafe extern "C" fn(),
    pub api_name: T,
    pub module_name: T,
}

#[macro_export]
macro_rules! ld_register {
    ($fn_name:ident, $module_name:ident, $new_fn:ident ) =>{
        paste::paste!{
            unsafe extern "C" {
                fn [<$new_fn _do_resolve>]();
            }
            static mut [<$new_fn:upper _RU>]:$crate::iat::LdResolverUnit<strobf::TObf> = $crate::iat::LdResolverUnit{
                addr:unsafe{std::mem::transmute([<$new_fn _do_resolve>] as *const fn())},
                api_name:$fn_name,
                module_name:$module_name
            };

            core::arch::global_asm!(
                concat!(".global ",stringify!($new_fn)),
                concat!(".global ",stringify!($new_fn),"_do_resolve"),
                ".section .text",
                concat!(stringify!($new_fn),":"),
                "   jmp [rip+{addr}]",
                concat!(stringify!($new_fn),"_do_resolve:"),
                "   lea rax, [rip+{addr}]",
                "   jmp resolve_primer",
                addr = sym [<$new_fn:upper _RU>],
            );
        }
    }
}

core::arch::global_asm!(
    ".global resolve_primer",
    ".section .text",
    "resolve_primer:",
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
    resolve = sym resolve::<strobf::TObf>,
);

#[macro_export]
macro_rules! ld_register2 {
    ($fn_name:expr, $module_name:ident, $new_fn:ident ) =>{
        paste::paste!{
            const [<OBF_ $new_fn:upper>]: strobf::TObf = strobf::TObf::new($fn_name);
            ld::ld_register!([<OBF_ $new_fn:upper>], $module_name, $new_fn);
        }
    }
}

#[macro_export]
macro_rules! ld_register3 {
    ($fn_name:ident, $module_name:ident ) =>{
        paste::paste!{
            const [<OBF_ $fn_name:upper>]: strobf::TObf = strobf::TObf::new(stringify!($fn_name));
            ld::ld_register!([<OBF_ $fn_name:upper>], $module_name, [<_ $fn_name>]);
        }
    }
}

pub unsafe extern "C" fn resolve<T: strobf::TStrObf<T>>(
    id: &mut LdResolverUnit<T>,
) -> unsafe extern "C" fn() {
    //TODO: cache module information
    let h_module = get_module_handle(&id.module_name);
    if h_module == null_mut() {
        obf_panic!("[ld] I couldn't resolve the module");
    }
    let proc_addr = get_proc_addr(h_module, &id.api_name);
    if proc_addr == null_mut() {
        obf_panic!("[ld] I couldn't resolve the function");
    } else {
        obf_println_info!("[ld] resolved {}::{} -> 0x{:08X}", id.module_name, id.api_name, proc_addr as usize);
        id.addr = unsafe{ std::mem::transmute(proc_addr) };
    }
    return id.addr;
}