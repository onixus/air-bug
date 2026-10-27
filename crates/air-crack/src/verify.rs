use subtle::ConstantTimeEq;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn mic_matches(computed: &[u8; 16], target: &[u8; 16]) -> bool {
    computed.ct_eq(target).into()
}
