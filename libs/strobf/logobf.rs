#[cfg(feature = "verbose_errors")]
#[macro_export]
macro_rules! obf_format_error {
    ($($arg:tt)*) => {
        format!($($arg)*)
    }
}
#[cfg(not( feature = "verbose_errors" ))]
#[macro_export]
macro_rules! obf_format_error {
    ($($arg:tt)*) => {
        "".to_string()
    }
}

#[cfg(feature = "verbose_errors")]
#[macro_export]
macro_rules! obf_panic{
    ($($arg:tt)*) => {
        panic!($($arg)*)
    };
}
#[cfg(not( feature = "verbose_errors" ))]
#[macro_export]
macro_rules! obf_panic {
    ($($arg:tt)*) => {
        panic!()
    }
}

#[cfg(feature = "verbose_errors")]
#[macro_export]
macro_rules! obf_println_error {
    ($($arg:tt)*) => {
        println!($($arg)*)
    }
}
#[cfg(not(feature = "verbose_errors"))]
#[macro_export]
macro_rules! obf_println_error {
    ($($arg:tt)*) => {
    }
}

#[cfg(feature = "verbose_info")]
#[macro_export]
macro_rules! obf_println_info {
    ($($arg:tt)*) => {
        println!($($arg)*)
    }
}
#[cfg(not(feature = "verbose_info"))]
#[macro_export]
macro_rules! obf_println_info {
    ($($arg:tt)*) => {
    }
}

#[cfg(feature = "verbose_debug")]
#[macro_export]
macro_rules! obf_println_debug {
    ($($arg:tt)*) => {
        println!($($arg)*)
    }
}
#[cfg(not(feature = "verbose_debug"))]
#[macro_export]
macro_rules! obf_println_debug {
    ($($arg:tt)*) => {
    }
}

//Converts any message into a hash and writes all parameters after it
// ("this is {:#?} a message {}", param1, param2)
// ("0xXXXXXXX - {:#?} - {}, param1, param2)
//Would then need to add hashes to original string format in an external file
/*const fn obf_fmt( fmt:&str ) -> (&str,u64){
    let mut cur = 0;
    let end = fmt.len();
    let start = fmt.as_ptr();
    let hash = crate::Djb2::new(fmt);
    let mut new_fmt = format!("0x{:08X}",hash.hash);
    while cur < end {
        unsafe{
            if *start.byte_add(cur) == '{' as u8{
                let mut next_cur = cur + 1;
                while next_cur < end && *start.byte_add(next_cur) != '}' as u8{
                    next_cur += 1;
                }
                let param_len = next_cur - cur + 1;
                let param = str::from_utf8_unchecked(std::slice::from_raw_parts(start.byte_add(cur), param_len));
                //TODO: new_fmt + " - " + param
            }
        }
    }
    return (new_fmt,hash.hash);
}
*/