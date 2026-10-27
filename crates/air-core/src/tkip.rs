//! IEEE 802.11 TKIP key mixing and Michael verification. AES-derived substitution
//! table is generated algebraically, not copied from a driver implementation.
use rc4::{
    cipher::{KeyInit, StreamCipher},
    consts::U16,
    Rc4,
};
use subtle::ConstantTimeEq;
const fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        a = (a << 1) ^ if a & 128 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    out
}
const fn table() -> [u16; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut inverse = if i == 0 { 0 } else { 1u8 };
        let mut n = 0;
        if i != 0 {
            while n < 254 {
                inverse = multiply(inverse, i as u8);
                n += 1;
            }
        }
        let value = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
        let twice = multiply(value, 2);
        table[i] = ((twice as u16) << 8) | ((twice ^ value) as u16);
        i += 1;
    }
    table
}
const SBOX: [u16; 256] = table();
fn substitution(value: u16) -> u16 {
    SBOX[value as u8 as usize] ^ SBOX[(value >> 8) as usize].swap_bytes()
}
fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes[..2].try_into().unwrap())
}
/// Per-packet RC4 seed; PN octets are TSC0..TSC5, least significant first.
pub fn seed(tk: &[u8; 16], transmitter: &[u8; 6], pn: &[u8; 6]) -> [u8; 16] {
    let tk: [u16; 8] = std::array::from_fn(|i| word(&tk[i * 2..]));
    let mut mix = [
        word(&pn[2..]),
        word(&pn[4..]),
        word(transmitter),
        word(&transmitter[2..]),
        word(&transmitter[4..]),
        0,
    ];
    for round in 0..8u16 {
        let parity = (round & 1) as usize;
        for index in 0..5 {
            let previous = if index == 0 { 4 } else { index - 1 };
            let k = if index == 4 {
                parity
            } else {
                2 * index + parity
            };
            mix[index] = mix[index].wrapping_add(substitution(mix[previous] ^ tk[k]));
        }
        mix[4] = mix[4].wrapping_add(round);
    }
    mix[5] = mix[4].wrapping_add(word(pn));
    for i in 0..6 {
        let previous = if i == 0 { 5 } else { i - 1 };
        mix[i] = mix[i].wrapping_add(substitution(mix[previous] ^ tk[i]));
    }
    for i in 0..6 {
        let previous = if i == 0 { 5 } else { i - 1 };
        let value = if i < 2 {
            mix[previous] ^ tk[6 + i]
        } else {
            mix[previous]
        };
        mix[i] = mix[i].wrapping_add(value.rotate_right(1));
    }
    let mut seed = [0; 16];
    seed[..4].copy_from_slice(&[
        pn[1],
        (pn[1] | 0x20) & 0x7f,
        pn[0],
        ((mix[5] ^ tk[0]) >> 1) as u8,
    ]);
    for (i, value) in mix.iter().enumerate() {
        seed[4 + i * 2..6 + i * 2].copy_from_slice(&value.to_le_bytes());
    }
    seed
}
fn michael_block(left: &mut u32, right: &mut u32, word: u32) {
    *left ^= word;
    *right ^= left.rotate_left(17);
    *left = left.wrapping_add(*right);
    *right ^= ((*left & 0xff00ff00) >> 8) | ((*left & 0x00ff00ff) << 8);
    *left = left.wrapping_add(*right);
    *right ^= left.rotate_left(3);
    *left = left.wrapping_add(*right);
    *right ^= left.rotate_right(2);
    *left = left.wrapping_add(*right);
}
pub fn michael(
    key: &[u8; 8],
    destination: &[u8; 6],
    source: &[u8; 6],
    priority: u8,
    payload: &[u8],
) -> [u8; 8] {
    let mut left = u32::from_le_bytes(key[..4].try_into().unwrap());
    let mut right = u32::from_le_bytes(key[4..].try_into().unwrap());
    let prefix = [
        destination.as_slice(),
        source.as_slice(),
        &[priority, 0, 0, 0],
    ]
    .concat();
    let mut partial = [0; 4];
    let mut count = 0;
    for &byte in prefix
        .iter()
        .chain(payload)
        .chain([0x5a, 0, 0, 0, 0].iter())
    {
        partial[count] = byte;
        count += 1;
        if count == 4 {
            michael_block(&mut left, &mut right, u32::from_le_bytes(partial));
            partial = [0; 4];
            count = 0;
        }
    }
    if count != 0 {
        michael_block(&mut left, &mut right, u32::from_le_bytes(partial));
    }
    let mut out = [0; 8];
    out[..4].copy_from_slice(&left.to_le_bytes());
    out[4..].copy_from_slice(&right.to_le_bytes());
    out
}
/// Verify both ICV and Michael before returning an MSDU. Fragmentation/reassembly
/// must be rejected by the caller; the final eight plaintext bytes are Michael.
pub fn decrypt(
    tk: &[u8; 16],
    mic_key: &[u8; 8],
    transmitter: &[u8; 6],
    destination: &[u8; 6],
    source: &[u8; 6],
    priority: u8,
    protected: &[u8],
) -> Option<Vec<u8>> {
    let plain = decrypt_mpdu(tk, transmitter, protected)?;
    verify_msdu(mic_key, destination, source, priority, plain)
}
/// RC4 and ICV per MPDU; Michael belongs to the assembled MSDU.
pub fn decrypt_mpdu(tk: &[u8; 16], transmitter: &[u8; 6], protected: &[u8]) -> Option<Vec<u8>> {
    if protected.len() < 12 {
        return None;
    }
    if protected[1] != (protected[0] | 0x20) & 0x7f || protected[3] & 0x3f != 0x20 {
        return None;
    }
    let pn = [
        protected[2],
        protected[0],
        protected[4],
        protected[5],
        protected[6],
        protected[7],
    ];
    let seed = seed(tk, transmitter, &pn);
    let mut plain = protected[8..].to_vec();
    Rc4::<U16>::new_from_slice(&seed)
        .ok()?
        .apply_keystream(&mut plain);
    let end = plain.len().checked_sub(4)?;
    if plain[end..] != crc32fast::hash(&plain[..end]).to_le_bytes() {
        return None;
    }
    plain.truncate(end);
    Some(plain)
}
pub fn verify_msdu(
    mic_key: &[u8; 8],
    destination: &[u8; 6],
    source: &[u8; 6],
    priority: u8,
    mut plain: Vec<u8>,
) -> Option<Vec<u8>> {
    let end = plain.len().checked_sub(8)?;
    let expected = michael(mic_key, destination, source, priority, &plain[..end]);
    if !bool::from(expected.ct_eq(&plain[end..])) {
        return None;
    }
    plain.truncate(end);
    Some(plain)
}
