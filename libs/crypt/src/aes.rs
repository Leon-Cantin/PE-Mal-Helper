use std::ptr::{null, null_mut};

use strobf::{obf_format_error, obf_println_info};
use windows_sys::Win32::
    Security::Cryptography::{
        BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_BLOCK_PADDING, BCRYPT_CHAIN_MODE_CBC,
        BCRYPT_CHAINING_MODE, BCRYPT_OBJECT_LENGTH, BCryptCloseAlgorithmProvider, BCryptDecrypt,
        BCryptDestroyKey, BCryptEncrypt, BCryptGenerateSymmetricKey, BCryptGetProperty,
        BCryptOpenAlgorithmProvider, BCryptSetProperty,
    }
;

#[macro_export]
macro_rules! wc {
    ($s:literal) => {{
        const INPUT: &[u8] = $s.as_bytes();
        const OUTPUT_LEN: usize = $crate::core::utf16_len(INPUT) + 1;
        const OUTPUT: &[u16; OUTPUT_LEN] = {
            let mut buffer = [0; OUTPUT_LEN];
            let mut input_pos = 0;
            let mut output_pos = 0;
            while let Some((mut code_point, new_pos)) =
                $crate::core::decode_utf8_char(INPUT, input_pos)
            {
                input_pos = new_pos;
                if code_point <= 0xffff {
                    buffer[output_pos] = code_point as u16;
                    output_pos += 1;
                } else {
                    code_point -= 0x10000;
                    buffer[output_pos] = 0xd800 + (code_point >> 10) as u16;
                    output_pos += 1;
                    buffer[output_pos] = 0xdc00 + (code_point & 0x3ff) as u16;
                    output_pos += 1;
                }
            }
            &{ buffer }
        };
        OUTPUT
    }};
}

const fn wstr_len(str: windows_sys::core::PCWSTR) -> usize {
    let mut i = 0;
    while unsafe { *str.wrapping_add(i) } != 0 {
        i += 1;
    }
    i
}

pub fn bcrypt_aes_encrypt(
    msg: &mut [u8],
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<Vec<u8>, String> {
    bcrypt_aes(true, msg, key, iv)
}

pub fn bcrypt_aes_decrypt(
    msg: &mut [u8],
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<Vec<u8>, String> {
    bcrypt_aes(false, msg, key, iv)
}

fn bcrypt_aes(enc: bool, msg: &mut [u8], key: &mut [u8], iv: &mut [u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut h_algorithm: BCRYPT_ALG_HANDLE = null_mut();
        let status = BCryptOpenAlgorithmProvider(&mut h_algorithm, BCRYPT_AES_ALGORITHM, null(), 0);

        if status < 0 {
            return Err(obf_format_error!(
                "[!] BCryptOpenAlgorithmProvider Failed: 0x{:08X}",
                status
            ));
        }

        let mut key_object_size: u32 = 0;
        let mut result = 0;
        BCryptGetProperty(
            h_algorithm,
            BCRYPT_OBJECT_LENGTH,
            &mut key_object_size as *mut _ as *mut u8,
            size_of::<u32>() as u32,
            &mut result,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!("[!] BCryptGetProperty[1] Failed: 0x{:08X}", status));
        }

        let mut key_object = vec![0 as u8; key_object_size as usize];

        const CHAINING_MODE: *const u16 = BCRYPT_CHAIN_MODE_CBC;
        const CHAINING_MODE_LEN: usize = wstr_len(CHAINING_MODE) * size_of::<u16>();
        let status = BCryptSetProperty(
            h_algorithm,
            BCRYPT_CHAINING_MODE,
            CHAINING_MODE as *const u8,
            CHAINING_MODE_LEN as u32,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!("[!] BCryptSetProperty failed: 0x{:08x}", status));
        }

        let mut h_key = null_mut();
        let status = BCryptGenerateSymmetricKey(
            h_algorithm,
            &mut h_key,
            key_object.as_mut_ptr(),
            key_object_size,
            key.as_ptr() as *mut _,
            key.len() as u32,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!(
                "[!] BCryptGenerateSymmetricKey failed: 0x{:08x}",
                status
            ));
        }

        let mut cypher_size = 0;
        let status = if enc {
            BCryptEncrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                null_mut(),
                0,
                &mut cypher_size,
                BCRYPT_BLOCK_PADDING,
            )
        } else {
            BCryptDecrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                null_mut(),
                0,
                &mut cypher_size,
                BCRYPT_BLOCK_PADDING,
            )
        };

        obf_println_info!("BCrypt1 success");
        if status < 0 {
            BCryptDestroyKey(h_key);
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!("[!] BCryptDecrypt[1] failed: 0x{:08x}", status));
        }

        let mut cypher_text = vec![0 as u8; cypher_size as usize];
        obf_println_info!("Need {} and vector is {}", cypher_size, cypher_text.len());

        let mut result = 0;
        let status = if enc {
            BCryptEncrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                cypher_text.as_mut_ptr(),
                cypher_size,
                &mut result,
                BCRYPT_BLOCK_PADDING,
            )
        } else {
            BCryptDecrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                cypher_text.as_mut_ptr(),
                cypher_size,
                &mut result,
                BCRYPT_BLOCK_PADDING,
            )
        };

        obf_println_info!("BCrypt2 success");

        BCryptDestroyKey(h_key);
        BCryptCloseAlgorithmProvider(h_algorithm, 0);

        if status < 0 {
            return Err(obf_format_error!("[!] BCryptDecrypt[2] failed: 0x{:08x}", status));
        }

        return Ok(cypher_text);
    }
}

pub fn bcrypt_aes_encrypt_inplace(
    msg: &mut [u8],
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<(), String> {
    bcrypt_aes_inplace(true, msg, key, iv)
}

pub fn bcrypt_aes_decrypt_inplace(
    msg: &mut [u8],
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<(), String> {
    bcrypt_aes_inplace(false, msg, key, iv)
}

fn bcrypt_aes_inplace(enc: bool, msg: &mut [u8], key: &mut [u8], iv: &mut [u8]) -> Result<(), String> {
    unsafe {
        let mut h_algorithm: BCRYPT_ALG_HANDLE = null_mut();
        let status = BCryptOpenAlgorithmProvider(&mut h_algorithm, BCRYPT_AES_ALGORITHM, null(), 0);

        if status < 0 {
            return Err(obf_format_error!(
                "[!] BCryptOpenAlgorithmProvider Failed: 0x{:08X}",
                status
            ));
        }

        let mut key_object_size: u32 = 0;
        let mut result = 0;
        BCryptGetProperty(
            h_algorithm,
            BCRYPT_OBJECT_LENGTH,
            &mut key_object_size as *mut _ as *mut u8,
            size_of::<u32>() as u32,
            &mut result,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!("[!] BCryptGetProperty[1] Failed: 0x{:08X}", status));
        }

        let mut key_object = vec![0 as u8; key_object_size as usize];

        const CHAINING_MODE: *const u16 = BCRYPT_CHAIN_MODE_CBC;
        const CHAINING_MODE_LEN: usize = wstr_len(CHAINING_MODE) * size_of::<u16>();
        let status = BCryptSetProperty(
            h_algorithm,
            BCRYPT_CHAINING_MODE,
            CHAINING_MODE as *const u8,
            CHAINING_MODE_LEN as u32,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!("[!] BCryptSetProperty failed: 0x{:08x}", status));
        }

        let mut h_key = null_mut();
        let status = BCryptGenerateSymmetricKey(
            h_algorithm,
            &mut h_key,
            key_object.as_mut_ptr(),
            key_object_size,
            key.as_ptr() as *mut _,
            key.len() as u32,
            0,
        );

        if status < 0 {
            BCryptCloseAlgorithmProvider(h_algorithm, 0);
            return Err(obf_format_error!(
                "[!] BCryptGenerateSymmetricKey failed: 0x{:08x}",
                status
            ));
        }

        let mut result = 0;
        let status = if enc {
            BCryptEncrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                msg.as_mut_ptr() as *mut _,
                msg.len() as u32,
                &mut result,
                BCRYPT_BLOCK_PADDING,
            )
        } else {
            BCryptDecrypt(
                h_key,
                msg.as_ptr() as *mut _,
                msg.len() as u32,
                null_mut(),
                iv.as_ptr() as *mut _,
                iv.len() as u32,
                msg.as_mut_ptr() as *mut _,
                msg.len() as u32,
                &mut result,
                BCRYPT_BLOCK_PADDING,
            )
        };

        obf_println_info!("BCrypt2 success");

        BCryptDestroyKey(h_key);
        BCryptCloseAlgorithmProvider(h_algorithm, 0);

        if status < 0 {
            return Err(obf_format_error!("[!] BCryptDecrypt[2] failed: 0x{:08x}", status));
        }

        return Ok(());
    }
}
