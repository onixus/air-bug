use air_core::{pmk, pmk_reference};
#[test]
fn specialized_pbkdf_matches_generic_at_wpa_boundaries_and_fallbacks() {
    for pass in [
        String::new(),
        "a".repeat(8),
        "p".repeat(63),
        "q".repeat(64),
        "r".repeat(65),
        "é".repeat(40),
    ] {
        for n in [0, 1, 31, 32, 33, 64] {
            let salt: Vec<_> = (0..n).map(|i| (i * 17) as u8).collect();
            assert_eq!(
                pmk(&pass, &salt),
                pmk_reference(&pass, &salt),
                "password bytes={} salt={n}",
                pass.len()
            );
        }
    }
    let mut state = 0x12345678u32;
    for n in 0..24 {
        let mut pass = String::new();
        for _ in 0..8 + n % 56 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            pass.push((32 + (state % 95) as u8) as char);
        }
        let salt: Vec<_> = (0..1 + n % 32)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                state as u8
            })
            .collect();
        assert_eq!(pmk(&pass, &salt), pmk_reference(&pass, &salt));
    }
}

#[test]
fn dictionary_kck_matches_full_ptk_for_sha1_and_sha256() {
    for index in 0..16u8 {
        let key = [index; 32];
        let ap = [2, 0, 0, 0, 0, index];
        let sta = [2, 0, 0, 0, 1, index];
        let an = [index.wrapping_add(1); 32];
        let sn = [index.wrapping_add(2); 32];
        for sha256 in [false, true] {
            let full = air_core::ptk_extended(&key, &ap, &sta, &an, &sn, sha256);
            assert_eq!(air_core::kck(&key, &ap, &sta, &an, &sn, sha256), full[..16]);
        }
    }
}
