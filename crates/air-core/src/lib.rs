use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

pub type MacAddr = [u8; 6];

mod pbkdf;

pub fn pmk(passphrase: &str, ssid: &[u8]) -> [u8; 32] {
    if passphrase.len() <= 64 && ssid.len() <= 32 {
        pbkdf::derive(passphrase.as_bytes(), ssid)
    } else {
        pmk_reference(passphrase, ssid)
    }
}

/// Generic RustCrypto baseline retained for differential tests and benchmarks.
pub fn pmk_reference(passphrase: &str, ssid: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid, 4096, &mut out);
    out
}

pub fn ptk(
    pmk: &[u8; 32],
    a: &[u8; 6],
    b: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 48] {
    ptk_extended(pmk, a, b, anonce, snonce, false)[..48]
        .try_into()
        .unwrap()
}

/// SHA1 PTK includes TKIP Michael keys; PSK-SHA256/CCMP derives exactly 384 bits.
pub fn ptk_extended(
    pmk: &[u8; 32],
    a: &[u8; 6],
    b: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    sha256: bool,
) -> [u8; 64] {
    let mut context = Vec::with_capacity(76);
    context.extend_from_slice(a.min(b));
    context.extend_from_slice(a.max(b));
    context.extend_from_slice(anonce.min(snonce));
    context.extend_from_slice(anonce.max(snonce));
    let mut out = [0; 64];
    if sha256 {
        for counter in 1..=2u16 {
            let mut mac: Hmac<sha2::Sha256> = Hmac::new_from_slice(pmk).expect("PMK");
            mac.update(&counter.to_le_bytes());
            mac.update(b"Pairwise key expansion");
            mac.update(&context);
            mac.update(&384u16.to_le_bytes());
            let digest = mac.finalize().into_bytes();
            let start = (counter as usize - 1) * 32;
            let len = (48 - start).min(32);
            out[start..start + len].copy_from_slice(&digest[..len]);
        }
    } else {
        for counter in 0..4u8 {
            let mut mac: Hmac<Sha1> = Hmac::new_from_slice(pmk).expect("PMK");
            mac.update(b"Pairwise key expansion\0");
            mac.update(&context);
            mac.update(&[counter]);
            let digest = mac.finalize().into_bytes();
            let start = counter as usize * 20;
            let len = (64 - start).min(20);
            out[start..start + len].copy_from_slice(&digest[..len]);
        }
    }
    out
}

/// Dictionary verification needs only KCK: the first 128 bits of PTK. Data
/// decryption still derives the complete PTK, including TKIP directional keys.
pub fn kck(
    pmk: &[u8; 32],
    a: &MacAddr,
    b: &MacAddr,
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    sha256: bool,
) -> [u8; 16] {
    let mut context = [0; 76];
    context[..6].copy_from_slice(a.min(b));
    context[6..12].copy_from_slice(a.max(b));
    context[12..44].copy_from_slice(anonce.min(snonce));
    context[44..].copy_from_slice(anonce.max(snonce));
    if sha256 {
        let mut mac: Hmac<sha2::Sha256> = Hmac::new_from_slice(pmk).expect("PMK");
        mac.update(&1u16.to_le_bytes());
        mac.update(b"Pairwise key expansion");
        mac.update(&context);
        mac.update(&384u16.to_le_bytes());
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    } else {
        let mut mac: Hmac<Sha1> = Hmac::new_from_slice(pmk).expect("PMK");
        mac.update(b"Pairwise key expansion\0");
        mac.update(&context);
        mac.update(&[0]);
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    }
}

pub fn mic(ptk: &[u8; 48], eapol: &[u8]) -> [u8; 16] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(&ptk[..16]).expect("ptk");
    mac.update(eapol);
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r[..16]);
    out
}

/// IEEE 802.11 WPA2-PSK PMKID: first 128 bits of HMAC-SHA1(PMK,
/// "PMK Name" || authenticator address || supplicant address).
/// Unlike PTK context, these MAC addresses MUST NOT be sorted.
pub fn pmkid(pmk: &[u8; 32], bssid: &MacAddr, sta: &MacAddr) -> [u8; 16] {
    let mut mac: Hmac<Sha1> = Hmac::new_from_slice(pmk).expect("fixed-length HMAC key");
    mac.update(b"PMK Name");
    mac.update(bssid);
    mac.update(sta);
    let digest = mac.finalize().into_bytes();
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// A WPA passphrase is 8..63 printable ASCII bytes.
pub fn valid_passphrase(candidate: &str) -> bool {
    (8..=63).contains(&candidate.len()) && candidate.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A dictionary candidate is a printable passphrase or an explicit 256-bit PSK.
pub fn candidate_pmk(candidate: &str, ssid: &[u8]) -> Option<[u8; 32]> {
    if candidate.len() == 64 {
        let mut key = [0; 32];
        hex::decode_to_slice(candidate, &mut key).ok()?;
        return Some(key);
    }
    valid_passphrase(candidate).then(|| pmk(candidate, ssid))
}

pub fn mic_version(ptk: &[u8; 48], eapol: &[u8], version: u8) -> Option<[u8; 16]> {
    match version {
        1 => {
            let mut mac: Hmac<md5::Md5> = Hmac::new_from_slice(&ptk[..16]).expect("KCK");
            mac.update(eapol);
            Some(mac.finalize().into_bytes().into())
        }
        2 => Some(mic(ptk, eapol)),
        0 | 3 => {
            use cmac::Mac;
            let mut mac =
                <cmac::Cmac<aes::Aes128> as cmac::Mac>::new_from_slice(&ptk[..16]).ok()?;
            mac.update(eapol);
            Some(mac.finalize().into_bytes().into())
        }
        _ => None,
    }
}

/// CCMP-128: 13-byte nonce and 8-byte authentication tag, authenticated before return.
pub fn decrypt_ccmp(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    use ccm::{
        aead::{Aead, Payload},
        consts::{U13, U8},
        Ccm,
    };
    type Cipher = Ccm<aes::Aes128, U8, U13>;
    let cipher = <Cipher as ccm::aead::KeyInit>::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

/// WEP40/WEP104: IV+secret RC4 key; return plaintext only after ICV validation.
pub fn decrypt_wep(secret: &[u8], iv: &[u8; 3], ciphertext: &[u8]) -> Option<Vec<u8>> {
    use rc4::{
        cipher::{KeyInit, StreamCipher},
        consts::{U16, U8},
        Rc4,
    };
    if ciphertext.len() < 4 {
        return None;
    }
    let mut key = iv.to_vec();
    key.extend_from_slice(secret);
    let mut data = ciphertext.to_vec();
    match secret.len() {
        5 => Rc4::<U8>::new_from_slice(&key)
            .ok()?
            .apply_keystream(&mut data),
        13 => Rc4::<U16>::new_from_slice(&key)
            .ok()?
            .apply_keystream(&mut data),
        _ => return None,
    }
    let end = data.len() - 4;
    if data[end..] != crc32fast::hash(&data[..end]).to_le_bytes() {
        return None;
    }
    data.truncate(end);
    Some(data)
}

pub mod tkip;

/// RFC3394 AES-128 unwrap with integrity-IV validation, before parsing KDEs.
pub fn unwrap_key_data(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    use subtle::ConstantTimeEq;
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return None;
    }
    let cipher = aes::Aes128::new_from_slice(kek).ok()?;
    let mut a: [u8; 8] = wrapped[..8].try_into().ok()?;
    let mut data = wrapped[8..].to_vec();
    let n = data.len() / 8;
    for round in (0..6).rev() {
        for index in (1..=n).rev() {
            let mut block = [0; 16];
            block[..8].copy_from_slice(
                &(u64::from_be_bytes(a) ^ ((round * n + index) as u64)).to_be_bytes(),
            );
            block[8..].copy_from_slice(&data[(index - 1) * 8..index * 8]);
            let mut block = block.into();
            cipher.decrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            data[(index - 1) * 8..index * 8].copy_from_slice(&block[8..]);
        }
    }
    bool::from(a.ct_eq(&[0xa6; 8])).then_some(data)
}
/// WPA1 group key data uses RC4(KeyIV || KEK), discarding its first 256 bytes.
pub fn unwrap_wpa1(kek: &[u8; 16], iv: &[u8; 16], encrypted: &[u8]) -> Option<Vec<u8>> {
    use rc4::{
        cipher::{KeyInit, StreamCipher},
        consts::U32,
        Rc4,
    };
    let mut seed = [0; 32];
    seed[..16].copy_from_slice(iv);
    seed[16..].copy_from_slice(kek);
    let mut cipher = Rc4::<U32>::new_from_slice(&seed).ok()?;
    cipher.apply_keystream(&mut [0; 256]);
    let mut data = encrypted.to_vec();
    cipher.apply_keystream(&mut data);
    Some(data)
}

/// IEEE 802.11 SHA256 KDF; labels omit a terminating NUL, integers are LE16.
pub fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8], length: usize) -> Option<Vec<u8>> {
    if length == 0 || length > 8191 {
        return None;
    }
    let mut out = Vec::with_capacity(length);
    for counter in 1..=length.div_ceil(32) {
        let mut mac: Hmac<sha2::Sha256> = Hmac::new_from_slice(key).ok()?;
        mac.update(&(counter as u16).to_le_bytes());
        mac.update(label);
        mac.update(context);
        mac.update(&((length * 8) as u16).to_le_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out.truncate(length);
    Some(out)
}

/// Internal key epoch binding for reassembly; never serialized or logged.
pub fn key_fingerprint(key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(key).into()
}
