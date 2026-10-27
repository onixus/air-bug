//! Unambiguous frequency-based radio identity; no regulatory permission implied.
use serde::Serialize;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RadioChannel {
    pub band: &'static str,
    pub channel: u16,
    pub frequency_mhz: u16,
}
pub fn from_frequency(freq: u16) -> Option<RadioChannel> {
    let (band, channel) = match freq {
        2484 => ("2.4GHz", 14),
        2412..=2472 if (freq - 2407).is_multiple_of(5) => ("2.4GHz", (freq - 2407) / 5),
        5160..=5885 if freq.is_multiple_of(5) => ("5GHz", (freq - 5000) / 5),
        5935 => ("6GHz", 2),
        5955..=7115 if (freq - 5950).is_multiple_of(5) => ("6GHz", (freq - 5950) / 5),
        _ => return None,
    };
    Some(RadioChannel {
        band,
        channel,
        frequency_mhz: freq,
    })
}
/// RNR channel numbers are interpreted using the advertised global operating
/// class; wider-channel numbers can denote a center rather than primary channel.
pub fn rnr_channel(op_class: u8, channel: u8) -> Option<RadioChannel> {
    if op_class == 81 && (1..=13).contains(&channel) {
        return from_frequency(2407 + u16::from(channel) * 5);
    }
    if op_class == 82 && channel == 14 {
        return from_frequency(2484);
    }
    if (115..=130).contains(&op_class) && (32..=177).contains(&channel) {
        return from_frequency(5000 + u16::from(channel) * 5);
    }
    if op_class == 136 && channel == 2 {
        return from_frequency(5935);
    }
    if matches!(op_class, 131..=135 | 137) && (1..=233).contains(&channel) {
        return from_frequency(5950 + u16::from(channel) * 5);
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_bands_and_special_channel() {
        assert_eq!(from_frequency(2412).unwrap().channel, 1);
        assert_eq!(from_frequency(5955).unwrap().channel, 1);
        assert_eq!(from_frequency(5955).unwrap().band, "6GHz");
        assert_eq!(from_frequency(5935).unwrap().channel, 2);
        assert_eq!(from_frequency(7115).unwrap().channel, 233);
        assert!(from_frequency(5945).is_none());
        assert_eq!(rnr_channel(136, 2).unwrap().frequency_mhz, 5935);
        assert!(rnr_channel(0, 1).is_none());
    }
}
