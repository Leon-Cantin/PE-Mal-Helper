use std::{ffi::CStr};
use widestring::WideCStr;

pub mod logobf;

#[cfg(feature="tobf_djb2")]
pub type TObf = Djb2;
pub trait TStrObf<T>: PartialEq + std::fmt::Display {
    fn obf_str(_str: &str) -> T;
    fn obf_cstr(_str: &CStr) -> T;
    fn obf_wcstr(_str: &WideCStr) -> T;
    fn eq_str(&self, _str: &str) -> bool;
    fn eq_cstr(&self, _str: &CStr) -> bool;
    fn eq_wcstr(&self, _str: &WideCStr) -> bool;
}

#[derive(PartialEq)]
pub struct Djb2 {
    pub hash: u64,
}

const SEED: u32 = 5;
const IV: u64 = 0x7331;

pub const fn djb2(data: &[u8]) -> Djb2 {
    let mut hash: u64 = IV;
    let mut i = 0;
    while i < data.len() {
        hash = hash
            .wrapping_shl(SEED)
            .wrapping_add(hash)
            .wrapping_add(data[i] as u64);
        i += 1;
    }
    Djb2 { hash }
}

pub const fn djb2_u16(data: &[u16]) -> Djb2 {
    let mut hash: u64 = IV;
    let mut i = 0;
    while i < data.len() {
        hash = hash
            .wrapping_shl(SEED)
            .wrapping_add(hash)
            .wrapping_add(data[i] as u8 as u64);
        i += 1;
    }
    Djb2 { hash }
}

impl Djb2 {
    pub const fn new(_str: &str) -> Self {
        return djb2(_str.as_bytes());
    }

    pub const fn from_cstr(_str: &CStr) -> Djb2 {
        return djb2(_str.to_bytes());
    }

    pub const fn from_wcstr(_str: &WideCStr) -> Djb2 {
        return djb2_u16(unsafe { std::slice::from_raw_parts(_str.as_ptr(), _str.len()) });
    }
}

impl TStrObf<Djb2> for Djb2 {
    fn obf_str(_str: &str) -> Djb2 {
        return Djb2::new(_str);
    }
    fn obf_cstr(_str: &CStr) -> Djb2 {
        return Djb2::from_cstr(_str);
    }
    fn obf_wcstr(_str: &WideCStr) -> Djb2 {
        return Djb2::from_wcstr(_str);
    }

    fn eq_str(&self, _str: &str) -> bool {
        *self == Djb2::new(_str)
    }
    fn eq_cstr(&self, _str: &CStr) -> bool {
        *self == Djb2::from_cstr(_str)
    }
    fn eq_wcstr(&self, _str: &WideCStr) -> bool {
        *self == Djb2::from_wcstr(_str)
    }
}

impl std::fmt::Display for Djb2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:08X}", self.hash)
    }
}

#[cfg(feature="tobf_raw")]
pub type TObf = Raw;

const RAW_SIZE: usize = 0x100;
#[derive(PartialEq)]
pub struct Raw {
    _str: [u8; RAW_SIZE],
    _len: usize,
}

impl Raw {
    pub const fn new(_str: &str) -> Self {
        let mut buf = [0u8; RAW_SIZE];
        assert!(_str.len() < RAW_SIZE);
        unsafe { std::ptr::copy_nonoverlapping(_str.as_ptr(), buf.as_mut_ptr(), _str.len()) };
        return Self {
            _str: buf,
            _len: _str.len(),
        };
    }
}

impl TStrObf<Raw> for Raw {
    fn obf_str(_str: &str) -> Self {
        unimplemented!();
    }
    fn obf_cstr(_str: &CStr) -> Self {
        unimplemented!();
    }
    fn obf_wcstr(_str: &WideCStr) -> Self {
        unimplemented!();
    }

    fn eq_str(&self, _str: &str) -> bool {
        let a_str = unsafe {
            str::from_utf8_unchecked(std::slice::from_raw_parts(self._str.as_ptr(), self._len))
        };
        a_str == _str
    }
    fn eq_cstr(&self, _str: &CStr) -> bool {
        let a_str = unsafe {
            str::from_utf8_unchecked(std::slice::from_raw_parts(self._str.as_ptr(), self._len))
        };
        a_str == _str.to_str().unwrap()
    }
    fn eq_wcstr(&self, _str: &WideCStr) -> bool {
        let a_str = unsafe {
            str::from_utf8_unchecked(std::slice::from_raw_parts(self._str.as_ptr(), self._len))
        };
        a_str == _str.to_string_lossy()
    }
}

impl std::fmt::Display for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", unsafe {
            str::from_utf8_unchecked(std::slice::from_raw_parts(self._str.as_ptr(), self._len))
        })
    }
}
