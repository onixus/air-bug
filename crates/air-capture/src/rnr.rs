//! Parse RNR records with known TBTT layouts; unknown types are not guessed.
use crate::radio::{self, RadioChannel};
use serde::Serialize;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Neighbor {
    pub operating_class: u8,
    pub channel: u8,
    pub radio: Option<RadioChannel>,
    pub bssid: Option<[u8; 6]>,
    pub short_ssid: Option<u32>,
    pub bss_parameters: Option<u8>,
    pub tbtt_offset: Option<u8>,
    pub tbtt_type: u8,
    pub tbtt_length: u8,
}
/// A malformed element rejects all its records so partial data is not promoted.
pub fn parse(mut data: &[u8]) -> Result<Vec<Neighbor>, &'static str> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err("truncated RNR header");
        }
        let head = data[0];
        let len = data[1] as usize;
        let op = data[2];
        let ch = data[3];
        data = &data[4..];
        let count = (head >> 4) as usize + 1;
        if len == 0 || count * len > data.len() {
            return Err("invalid RNR TBTT length");
        }
        for item in data[..count * len].chunks_exact(len) {
            let ty = head & 3;
            let known = ty == 0;
            let bssid = if known && (matches!(len, 7..=9) || len >= 11) {
                let a: [u8; 6] = item[1..7].try_into().unwrap();
                if a != [0; 6] && a[0] & 1 == 0 {
                    Some(a)
                } else {
                    None
                }
            } else {
                None
            };
            let short_ssid = if known && len >= 11 {
                Some(u32::from_le_bytes(item[7..11].try_into().unwrap()))
            } else {
                None
            };
            let bss_parameters = if known && matches!(len, 8 | 9) {
                Some(item[7])
            } else if known && len >= 12 {
                Some(item[11])
            } else {
                None
            };
            out.push(Neighbor {
                operating_class: op,
                channel: ch,
                radio: radio::rnr_channel(op, ch),
                bssid,
                short_ssid,
                bss_parameters,
                tbtt_offset: if known { item.first().copied() } else { None },
                tbtt_type: ty,
                tbtt_length: len as u8,
            });
        }
        data = &data[count * len..];
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiple_entries_and_malformed_are_bounded() {
        let mut bytes = vec![0x10, 8, 131, 5];
        bytes.extend([1, 2, 1, 2, 3, 4, 5, 0x02]);
        bytes.extend([2, 2, 9, 8, 7, 6, 5, 0]);
        let entries = parse(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].radio.unwrap().frequency_mhz, 5975);
        assert_eq!(entries[0].bssid, Some([2, 1, 2, 3, 4, 5]));
        assert_eq!(entries[0].bss_parameters, Some(2));
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse(&[0, 0, 131, 1]).is_err());
        let unknown = parse(&[1, 8, 131, 1, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert!(unknown[0].bssid.is_none());
    }
}
