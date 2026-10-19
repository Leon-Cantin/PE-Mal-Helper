use windows_sys::Win32::{
    Foundation::NTSTATUS,
    Security::Cryptography::{
        BCRYPT_ALG_HANDLE, BCRYPT_FLAGS, BCRYPT_HANDLE, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    },
};

const OBF_BCRYPT_DLL: strobf::TObf = strobf::TObf::new("bcrypt.dll");

ld::ld_register2!(
    "BCryptOpenAlgorithmProvider",
    OBF_BCRYPT_DLL,
    bcrypt_open_algorithm_provider
);
unsafe extern "C" {
    pub fn bcrypt_open_algorithm_provider(
        phalgorithm: *mut BCRYPT_ALG_HANDLE,
        pszalgid: windows_sys::core::PCWSTR,
        pszimplementation: windows_sys::core::PCWSTR,
        dwflags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    ) -> NTSTATUS;
}

ld::ld_register2!("BCryptGetProperty", OBF_BCRYPT_DLL, bcrypt_get_property);
unsafe extern "C" {
    pub fn bcrypt_get_property(
        hobject: BCRYPT_HANDLE,
        pszproperty: windows_sys::core::PCWSTR,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: u32,
    ) -> NTSTATUS;
}

ld::ld_register2!(
    "BCryptCloseAlgorithmProvider",
    OBF_BCRYPT_DLL,
    bcrypt_close_algorithm_provider
);
unsafe extern "C" {
    pub fn bcrypt_close_algorithm_provider(halgorithm: BCRYPT_ALG_HANDLE, dwflags: u32)
    -> NTSTATUS;
}

ld::ld_register2!("BCryptSetProperty", OBF_BCRYPT_DLL, bcrypt_set_property);
unsafe extern "C" {
    pub fn bcrypt_set_property(
        hobject: BCRYPT_HANDLE,
        pszproperty: windows_sys::core::PCWSTR,
        pbinput: *const u8,
        cbinput: u32,
        dwflags: u32,
    ) -> NTSTATUS;
}

ld::ld_register2!(
    "BCryptGenerateSymmetricKey",
    OBF_BCRYPT_DLL,
    bcrypt_generate_symmetric_key
);
unsafe extern "C" {
    pub fn bcrypt_generate_symmetric_key(
        halgorithm: BCRYPT_ALG_HANDLE,
        phkey: *mut BCRYPT_KEY_HANDLE,
        pbkeyobject: *mut u8,
        cbkeyobject: u32,
        pbsecret: *const u8,
        cbsecret: u32,
        dwflags: u32,
    ) -> NTSTATUS;
}

ld::ld_register2!("BCryptEncrypt", OBF_BCRYPT_DLL, bcrypt_encrypt);
unsafe extern "C" {
    pub fn bcrypt_encrypt(
        hkey: BCRYPT_KEY_HANDLE,
        pbinput: *const u8,
        cbinput: u32,
        ppaddinginfo: *const core::ffi::c_void,
        pbiv: *mut u8,
        cbiv: u32,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: BCRYPT_FLAGS,
    ) -> NTSTATUS;
}

ld::ld_register2!("BCryptDecrypt", OBF_BCRYPT_DLL, bcrypt_decrypt);
unsafe extern "C" {
    pub fn bcrypt_decrypt(
        hkey: BCRYPT_KEY_HANDLE,
        pbinput: *const u8,
        cbinput: u32,
        ppaddinginfo: *const core::ffi::c_void,
        pbiv: *mut u8,
        cbiv: u32,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: BCRYPT_FLAGS,
    ) -> NTSTATUS;
}

ld::ld_register2!("BCryptDestroyKey", OBF_BCRYPT_DLL, bcrypt_destroy_key);
unsafe extern "C" {
    pub fn bcrypt_destroy_key(hkey: BCRYPT_KEY_HANDLE) -> NTSTATUS;
}
