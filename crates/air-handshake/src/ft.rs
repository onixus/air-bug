//! Bounded FT-PSK / FT-SAE reassociation verifier (CCMP-128, SHA256 hierarchy).
use air_core::{kdf_sha256, mic_version, MacAddr};
use air_frames::{Dot11Frame, FrameKind};
#[derive(Debug, Clone)]
pub struct FtSession {
    pub bssid: MacAddr,
    pub sta: MacAddr,
    pub akm: u8,
    pub transaction: u8,
    pub mdid: [u8; 2],
    pub r0kh: Vec<u8>,
    pub r1kh: [u8; 6],
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub mic: [u8; 16],
    pub mic_data: Vec<u8>,
    pub gtk: Option<Vec<u8>>,
    pub r1_name: [u8; 16],
}
impl FtSession {
    pub fn derive(&self, pmk: &[u8; 32], ssid: &[u8]) -> Option<[u8; 64]> {
        use sha2::{Digest, Sha256};
        if ssid.is_empty()
            || ssid.len() > 32
            || !matches!(self.akm, 4 | 9)
            || self.r0kh.is_empty()
            || self.r0kh.len() > 48
        {
            return None;
        }
        let mut context = vec![ssid.len() as u8];
        context.extend_from_slice(ssid);
        context.extend(self.mdid);
        context.push(self.r0kh.len() as u8);
        context.extend(&self.r0kh);
        context.extend(self.sta);
        let r0 = kdf_sha256(pmk, b"FT-R0", &context, 48)?;
        let mut hash = Sha256::new();
        hash.update(b"FT-R0N");
        hash.update(&r0[32..]);
        let r0_name = hash.finalize();
        let context = [self.r1kh.as_slice(), self.sta.as_slice()].concat();
        let r1 = kdf_sha256(&r0[..32], b"FT-R1", &context, 32)?;
        hash = Sha256::new();
        hash.update(b"FT-R1N");
        hash.update(&r0_name[..16]);
        hash.update(&context);
        let name = hash.finalize();
        use subtle::ConstantTimeEq;
        if !bool::from(name[..16].ct_eq(&self.r1_name)) {
            return None;
        }
        let context = [
            self.snonce.as_slice(),
            self.anonce.as_slice(),
            self.bssid.as_slice(),
            self.sta.as_slice(),
        ]
        .concat();
        let ptk = kdf_sha256(&r1, b"FT-PTK", &context, 48)?;
        let mut out = [0; 64];
        out[..48].copy_from_slice(&ptk);
        Some(out)
    }
    pub fn verified_ptk(&self, pmk: &[u8; 32], ssid: &[u8]) -> Option<[u8; 64]> {
        use subtle::ConstantTimeEq;
        let ptk = self.derive(pmk, ssid)?;
        let mic = mic_version(ptk[..48].try_into().ok()?, &self.mic_data, 3)?;
        bool::from(mic.ct_eq(&self.mic)).then_some(ptk)
    }
}
fn ies(mut bytes: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = *bytes.get(1)? as usize;
        out.push((bytes[0], bytes.get(..2 + len)?));
        bytes = &bytes[2 + len..];
    }
    Some(out)
}
pub fn parse(frame: &Dot11Frame) -> Option<FtSession> {
    if frame.kind != FrameKind::Mgmt || frame.frame_control & 0xc700 != 0 {
        return None;
    }
    let (fixed, transaction, ap, sta) = match frame.frame_control & 0xf0 {
        0x20 => (10, 5, frame.addr1, frame.addr2),
        0x30 => {
            if frame.payload.get(2..4)? != [0, 0] {
                return None;
            }
            (6, 6, frame.addr2, frame.addr1)
        }
        _ => return None,
    };
    if ap != frame.addr3
        || ap == sta
        || ap == [0; 6]
        || sta == [0; 6]
        || ap[0] & 1 != 0
        || sta[0] & 1 != 0
    {
        return None;
    }
    let parts = ies(frame.payload.get(fixed..)?)?;
    // RIC/RSNXE expand the signed IE list and require their own verification path.
    if parts.iter().any(|(id, _)| matches!(id, 57 | 244)) {
        return None;
    }
    let one = |id| {
        let mut found = parts.iter().filter(|(n, _)| *n == id);
        let (_, bytes) = found.next()?;
        if found.next().is_some() {
            None
        } else {
            Some(*bytes)
        }
    };
    let rsn = one(48)?;
    let md = one(54)?;
    let ft = one(55)?;
    if md.len() != 5 || ft.len() < 84 || ft[2..4] != [0, 3] {
        return None;
    }
    let p = super::negotiated_psk(rsn)?;
    if !matches!(p.akm, 4 | 9) || p.cipher != 4 || p.group_cipher != 4 {
        return None;
    }
    if rsn.get(22..24)? != [1, 0] {
        return None;
    }
    let r1_name = rsn.get(24..40)?.try_into().ok()?;
    let mic: [u8; 16] = ft[4..20].try_into().ok()?;
    let anonce = ft[20..52].try_into().ok()?;
    let snonce = ft[52..84].try_into().ok()?;
    if mic == [0; 16] || anonce == [0; 32] || snonce == [0; 32] {
        return None;
    }
    let sub = ies(&ft[84..])?;
    let find = |id| {
        let mut matches = sub.iter().filter(|(n, _)| *n == id);
        let (_, bytes) = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(&bytes[2..])
        }
    };
    let r0kh = find(3)?.to_vec();
    if r0kh.is_empty() || r0kh.len() > 48 {
        return None;
    }
    let r1kh = find(1)?.try_into().ok()?;
    if sub.iter().filter(|(id, _)| *id == 2).count() > 1 {
        return None;
    }
    let gtk = find(2).map(|v| v.to_vec());
    if transaction == 5 && gtk.is_some() {
        return None;
    }
    let mut zero = ft.to_vec();
    zero[4..20].fill(0);
    let mic_data = [
        sta.as_slice(),
        ap.as_slice(),
        &[transaction],
        rsn,
        md,
        &zero,
    ]
    .concat();
    Some(FtSession {
        bssid: ap,
        sta,
        akm: p.akm,
        transaction,
        mdid: md[2..4].try_into().ok()?,
        r0kh,
        r1kh,
        anonce,
        snonce,
        mic,
        mic_data,
        gtk,
        r1_name,
    })
}
