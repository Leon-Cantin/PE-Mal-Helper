pub mod aes;

pub const fn xor(data: &mut [u8], key: &[u8]) {
    let mut i = 0;
    let len = data.len();
    while i < len {
        let ik = i % key.len();
        data[i] = data[i] ^ key[ik];
        i += 1;
    }
}