//! WPA's fixed PBKDF2-HMAC-SHA1 shape using RustCrypto's dispatched SHA-1
//! compression primitive. Password pads are compressed once; U2..U4096 are
//! always exactly 20 bytes, so their padding and length are fixed.
use sha1::block_api::compress;
const INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
fn words_into(words: &[u32; 5], out: &mut [u8]) {
    for (word, bytes) in words.iter().zip(out.as_chunks_mut::<4>().0) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
}
fn digest_pad(state: &[u32; 5], block: &[u8; 64]) -> [u32; 5] {
    let mut out = *state;
    compress(&mut out, std::slice::from_ref(block));
    out
}
pub fn derive(password: &[u8], salt: &[u8]) -> [u8; 32] {
    debug_assert!(password.len() <= 64 && salt.len() <= 32);
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (i, byte) in password.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let inner = digest_pad(&INITIAL, &inner);
    let outer = digest_pad(&INITIAL, &outer);
    let mut fixed = [0u8; 64];
    fixed[20] = 0x80;
    fixed[56..].copy_from_slice(&(84u64 * 8).to_be_bytes());
    let mut blocks = [fixed; 2];
    let mut u = [[0; 5]; 2];
    for index in 0..2 {
        let mut first = [0u8; 64];
        first[..salt.len()].copy_from_slice(salt);
        first[salt.len()..salt.len() + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
        first[salt.len() + 4] = 0x80;
        first[56..].copy_from_slice(&((64 + salt.len() as u64 + 4) * 8).to_be_bytes());
        let digest = digest_pad(&inner, &first);
        words_into(&digest, &mut blocks[index][..20]);
        u[index] = digest_pad(&outer, &blocks[index]);
    }
    let mut totals = u;
    for _ in 1..4096 {
        words_into(&u[0], &mut blocks[0][..20]);
        words_into(&u[1], &mut blocks[1][..20]);
        let left = digest_pad(&inner, &blocks[0]);
        let right = digest_pad(&inner, &blocks[1]);
        words_into(&left, &mut blocks[0][..20]);
        words_into(&right, &mut blocks[1][..20]);
        u[0] = digest_pad(&outer, &blocks[0]);
        u[1] = digest_pad(&outer, &blocks[1]);
        for index in 0..2 {
            for (total, word) in totals[index].iter_mut().zip(u[index]) {
                *total ^= word;
            }
        }
    }
    let mut out = [0; 32];
    let mut bytes = [0; 20];
    words_into(&totals[0], &mut bytes);
    out[..20].copy_from_slice(&bytes);
    words_into(&totals[1], &mut bytes);
    out[20..].copy_from_slice(&bytes[..12]);
    out
}
