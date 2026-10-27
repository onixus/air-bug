//! Passive advertisement parsing; fields are observations, not negotiated or
//! authenticated security state. Unknown selectors are retained as wire IDs.
use serde::Serialize;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suite {
    pub selector: String,
    pub name: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub group_cipher: Option<Suite>,
    pub pairwise_ciphers: Vec<Suite>,
    pub akm_suites: Vec<Suite>,
    pub capabilities: Option<u16>,
    pub pmf: &'static str,
    pub group_management_cipher: Option<Suite>,
    /// false means the element uses omitted/default fields; no defaults guessed.
    pub explicit_core_fields: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rsnxe {
    pub raw_hex: String,
    pub sae_h2e: bool,
    pub sae_pk: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OweTransition {
    pub peer_bssid_hex: String,
    pub peer_ssid_hex: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: &'static str,
    pub evidence: &'static str,
    pub recommendation: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub advertised_mode: &'static str,
    pub findings: Vec<Finding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdvertisedSecurity {
    pub privacy: bool,
    pub rsn: Option<Profile>,
    pub wpa: Option<Profile>,
    pub rsnxe: Option<Rsnxe>,
    pub owe_transition: Option<OweTransition>,
    pub assessment: Assessment,
    pub observations: Vec<&'static str>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SecurityObservation {
    /// 1-based record number in the survey input, not a packet byte offset.
    pub record_index: u64,
    pub source: &'static str,
    pub observed_processing_seconds: f64,
    pub advertised: AdvertisedSecurity,
}
fn suite(bytes: &[u8], akm: bool) -> Suite {
    let selector = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let name = match (bytes, akm) {
        ([0, 15, 172, 1], true) => "802.1X",
        ([0, 15, 172, 2], true) => "PSK",
        ([0, 15, 172, 3], true) => "FT-802.1X",
        ([0, 15, 172, 4], true) => "FT-PSK",
        ([0, 15, 172, 5], true) => "802.1X-SHA256",
        ([0, 15, 172, 6], true) => "PSK-SHA256",
        ([0, 15, 172, 8], true) => "SAE",
        ([0, 15, 172, 9], true) => "FT-SAE",
        ([0, 15, 172, 11], true) => "802.1X-Suite-B",
        ([0, 15, 172, 12], true) => "802.1X-Suite-B-192",
        ([0, 15, 172, 13], true) => "FT-802.1X-SHA384",
        ([0, 15, 172, 14], true) => "FILS-SHA256",
        ([0, 15, 172, 15], true) => "FILS-SHA384",
        ([0, 15, 172, 16], true) => "FT-FILS-SHA256",
        ([0, 15, 172, 17], true) => "FT-FILS-SHA384",
        ([0, 15, 172, 18], true) => "OWE",
        ([0, 15, 172, 21], true) => "PASN",
        ([80, 111, 154, 2], true) => "DPP",
        ([0, 80, 242, 1], true) => "802.1X",
        ([0, 80, 242, 2], true) => "PSK",
        ([0, 15, 172, 0], false) => "USE-GROUP",
        ([0, 15, 172, 1], false) => "WEP-40",
        ([0, 15, 172, 2], false) | ([0, 80, 242, 2], false) => "TKIP",
        ([0, 15, 172, 4], false) | ([0, 80, 242, 4], false) => "CCMP-128",
        ([0, 15, 172, 5], false) => "WEP-104",
        ([0, 15, 172, 6], false) => "BIP-CMAC-128",
        ([0, 15, 172, 7], false) => "NO-GROUP-TRAFFIC",
        ([0, 15, 172, 8], false) => "GCMP-128",
        ([0, 15, 172, 9], false) => "GCMP-256",
        ([0, 15, 172, 10], false) => "CCMP-256",
        ([0, 15, 172, 11], false) => "BIP-GMAC-128",
        ([0, 15, 172, 12], false) => "BIP-GMAC-256",
        ([0, 15, 172, 13], false) => "BIP-CMAC-256",
        _ => "UNKNOWN",
    };
    Suite { selector, name }
}
fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], ()> {
    let (head, tail) = data.split_at_checked(n).ok_or(())?;
    *data = tail;
    Ok(head)
}
fn count_list(data: &mut &[u8], akm: bool) -> Result<Vec<Suite>, ()> {
    let count = u16::from_le_bytes(take(data, 2)?.try_into().map_err(|_| ())?) as usize;
    if count == 0 || count > data.len() / 4 {
        return Err(());
    }
    let bytes = take(data, count * 4)?;
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| suite(b, akm))
        .collect())
}
fn profile(mut data: &[u8], legacy: bool) -> Result<Profile, ()> {
    if take(&mut data, 2)? != [1, 0] {
        return Err(());
    }
    let mut result = Profile {
        group_cipher: None,
        pairwise_ciphers: Vec::new(),
        akm_suites: Vec::new(),
        capabilities: None,
        pmf: "unknown",
        group_management_cipher: None,
        explicit_core_fields: false,
    };
    if data.is_empty() {
        return Ok(result);
    }
    result.group_cipher = Some(suite(take(&mut data, 4)?, false));
    if data.is_empty() {
        return Ok(result);
    }
    result.pairwise_ciphers = count_list(&mut data, false)?;
    if data.is_empty() {
        return Ok(result);
    }
    result.akm_suites = count_list(&mut data, true)?;
    result.explicit_core_fields = true;
    if data.is_empty() {
        return Ok(result);
    }
    let caps = u16::from_le_bytes(take(&mut data, 2)?.try_into().map_err(|_| ())?);
    result.capabilities = Some(caps);
    if !legacy {
        result.pmf = match (caps & 0x80 != 0, caps & 0x40 != 0) {
            (false, false) => "not_capable",
            (true, false) => "optional",
            (true, true) => "required",
            (false, true) => "inconsistent",
        };
    }
    if legacy {
        return if data.is_empty() { Ok(result) } else { Err(()) };
    }
    if data.is_empty() {
        return Ok(result);
    }
    let n = u16::from_le_bytes(take(&mut data, 2)?.try_into().map_err(|_| ())?) as usize;
    if n > data.len() / 16 {
        return Err(());
    }
    take(&mut data, n * 16)?;
    if !data.is_empty() {
        result.group_management_cipher = Some(suite(take(&mut data, 4)?, false));
    }
    if !data.is_empty() {
        return Err(());
    }
    Ok(result)
}
fn has(profile: &Profile, names: &[&str]) -> bool {
    profile.akm_suites.iter().any(|x| names.contains(&x.name))
}
pub(crate) fn parse(mut ies: &[u8], privacy: bool) -> Result<AdvertisedSecurity, ()> {
    let (mut rsn, mut wpa, mut rsnxe, mut owe_transition) = (None, None, None, None);
    while !ies.is_empty() {
        let id = *take(&mut ies, 1)?.first().ok_or(())?;
        let len = *take(&mut ies, 1)?.first().ok_or(())? as usize;
        let value = take(&mut ies, len)?;
        match id {
            48 => {
                if rsn.is_some() {
                    return Err(());
                }
                rsn = Some(profile(value, false)?);
            }
            221 if value.starts_with(&[0, 80, 242, 1]) => {
                if wpa.is_some() {
                    return Err(());
                }
                wpa = Some(profile(&value[4..], true)?);
            }
            221 if value.starts_with(&[0x50, 0x6f, 0x9a, 0x1c]) => {
                if owe_transition.is_some() || value.len() < 11 {
                    return Err(());
                }
                let ssid_len = value[10] as usize;
                if ssid_len > 32 || value.len() < 11 + ssid_len {
                    return Err(());
                }
                owe_transition = Some(OweTransition {
                    peer_bssid_hex: value[4..10].iter().map(|b| format!("{b:02x}")).collect(),
                    peer_ssid_hex: value[11..11 + ssid_len]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                });
            }
            244 => {
                if rsnxe.is_some()
                    || value.is_empty()
                    || (value[0] & 15) as usize + 1 != value.len()
                {
                    return Err(());
                }
                rsnxe = Some(Rsnxe {
                    raw_hex: value.iter().map(|b| format!("{b:02x}")).collect(),
                    sae_h2e: value[0] & 0x20 != 0,
                    sae_pk: value[0] & 0x40 != 0,
                });
            }
            _ => {}
        }
    }
    let mut observations = Vec::new();
    if rsn.is_none() && wpa.is_none() {
        observations.push(if privacy {
            "privacy_without_rsn_or_wpa"
        } else {
            "open_advertisement"
        });
    }
    if wpa.is_some() {
        observations.push("legacy_wpa_advertised");
    }
    if !privacy && (rsn.is_some() || wpa.is_some()) {
        observations.push("privacy_bit_absent_with_security_ie");
    }
    for item in [rsn.as_ref(), wpa.as_ref()].into_iter().flatten() {
        if item
            .group_cipher
            .iter()
            .chain(item.pairwise_ciphers.iter())
            .any(|s| matches!(s.name, "WEP-40" | "WEP-104" | "TKIP"))
            && !observations.contains(&"legacy_cipher_advertised")
        {
            observations.push("legacy_cipher_advertised");
        }
        if item.akm_suites.iter().any(|s| s.name == "UNKNOWN")
            && !observations.contains(&"unknown_akm_selector")
        {
            observations.push("unknown_akm_selector");
        }
        if item.pmf == "optional" {
            observations.push("pmf_optional_advertised");
        }
        if item.pmf == "not_capable" {
            observations.push("pmf_not_capable_advertised");
        }
        if item.pmf == "inconsistent" {
            observations.push("inconsistent_pmf_bits");
        }
        if has(item, &["SAE", "FT-SAE"]) && has(item, &["PSK", "FT-PSK", "PSK-SHA256"]) {
            observations.push("sae_psk_transition_advertised");
        }
        if !item.explicit_core_fields {
            observations.push("omitted_rsn_fields_not_inferred");
        }
    }
    let assessment = assess(privacy, rsn.as_ref(), wpa.as_ref(), owe_transition.as_ref());
    Ok(AdvertisedSecurity {
        privacy,
        rsn,
        wpa,
        rsnxe,
        owe_transition,
        assessment,
        observations,
    })
}

// These are advice based on a single unauthenticated advertisement, not a
// certification, a negotiated session, or proof that a companion BSS exists.
fn assess(
    privacy: bool,
    rsn: Option<&Profile>,
    wpa: Option<&Profile>,
    transition: Option<&OweTransition>,
) -> Assessment {
    let sae = rsn.is_some_and(|p| has(p, &["SAE", "FT-SAE"]));
    let psk = rsn.is_some_and(|p| has(p, &["PSK", "FT-PSK", "PSK-SHA256"]));
    let owe = rsn.is_some_and(|p| has(p, &["OWE"]));
    let mode = if owe && sae {
        "mixed_owe_sae"
    } else if owe {
        "owe_advertised"
    } else if sae && psk {
        "sae_psk_transition"
    } else if sae {
        "sae_advertised"
    } else if rsn.is_some_and(|p| !p.explicit_core_fields) {
        "rsn_incomplete"
    } else if rsn.is_some() {
        "other_rsn"
    } else if wpa.is_some() {
        "legacy_wpa"
    } else if privacy {
        "privacy_unknown"
    } else {
        "open_advertised"
    };
    let mut findings = Vec::new();
    let mut add = |id, severity, evidence, recommendation| {
        findings.push(Finding {
            id,
            severity,
            evidence,
            recommendation,
        })
    };
    if transition.is_some() {
        add("owe_transition_advertised", "info", "OWE transition element points to another BSSID; its existence and identity have not been verified.", "Review the open companion BSS; legacy clients may connect without wireless encryption. Prefer OWE-only where clients support it.");
    }
    if owe {
        add("owe_no_peer_authentication", "info", "The OWE AKM is advertised.", "OWE encrypts the wireless link but does not authenticate the access point. Use authenticated end-to-end protocols or an authenticated network where identity matters.");
    }
    if sae && psk {
        add("sae_psk_transition", "info", "SAE and PSK AKMs are advertised together.", "Transition mode supports legacy PSK clients. After checking client compatibility, consider SAE-only and required PMF.");
    }
    if sae && owe {
        add("mixed_owe_sae", "review", "OWE and SAE AKMs appear in the same RSN element.", "Review the intended AP configuration and verify the advertisement with a fresh capture.");
    }
    if let Some(p) = rsn {
        if !p.explicit_core_fields || p.pmf == "unknown" {
            add("rsn_details_unknown", "unknown", "The RSN element omits core fields or PMF capabilities.", "Inspect the AP configuration or obtain a complete, current advertisement; do not assume the missing values.");
        }
        if p.pmf == "inconsistent" {
            add(
                "pmf_bits_inconsistent",
                "review",
                "The advertisement sets MFPR without MFPC.",
                "Check AP PMF configuration and confirm the RSN element in a fresh capture.",
            );
        }
        if (sae || owe) && p.pmf == "not_capable" {
            add("modern_akm_without_pmf_capability", "review", "SAE or OWE is advertised while MFPC is clear.", "Enable PMF capability and verify client interoperability and the intended security mode.");
        }
        if (sae || owe) && p.pmf == "optional" && !(sae && psk) {
            add("modern_akm_pmf_optional", "review", "SAE or OWE is advertised with PMF optional.", "Consider requiring PMF after verifying client compatibility and the actual configured mode.");
        }
        if !sae && !owe && p.pmf == "not_capable" {
            add(
                "pmf_not_capable",
                "review",
                "The RSN capabilities advertise no PMF capability.",
                "Enable PMF where supported, then require it when all clients are compatible.",
            );
        }
        if p.akm_suites
            .iter()
            .chain(p.pairwise_ciphers.iter())
            .chain(p.group_cipher.iter())
            .any(|x| x.name == "UNKNOWN")
        {
            add("unknown_suite", "unknown", "At least one advertised AKM or cipher selector is not recognized.", "Inspect the raw selector and AP configuration before judging compatibility or security.");
        }
    }
    if [rsn, wpa].into_iter().flatten().any(|p| {
        p.group_cipher
            .iter()
            .chain(p.pairwise_ciphers.iter())
            .any(|s| matches!(s.name, "WEP-40" | "WEP-104" | "TKIP"))
    }) {
        add("legacy_cipher", "review", "WEP or TKIP is advertised as a group or pairwise cipher.", "Replace legacy ciphers with modern supported ciphers after checking client compatibility.");
    }
    if wpa.is_some() {
        add(
            "legacy_wpa",
            "review",
            "A legacy WPA vendor element is advertised.",
            "Retire legacy WPA when all clients support an appropriate modern mode.",
        );
    }
    if !privacy && (rsn.is_some() || wpa.is_some()) {
        add(
            "privacy_bit_conflict",
            "review",
            "An RSN or WPA element is present while the privacy capability bit is clear.",
            "Check the AP configuration and validate a fresh beacon or probe response.",
        );
    }
    if rsn.is_none() && wpa.is_none() && transition.is_none() {
        if privacy {
            add("privacy_unknown", "unknown", "The privacy bit is set without an RSN or WPA element.", "Inspect the AP configuration; the advertised security cannot be identified from this frame alone.");
        } else {
            add("open_bss", "review", "No RSN or WPA element and no privacy bit were observed in this advertisement.", "Consider OWE or an authenticated wireless network when supported; verify the intended deployment and other advertisements.");
        }
    }
    Assessment {
        advertised_mode: mode,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rsn(akms: &[u8], caps: Option<u16>) -> Vec<u8> {
        let mut value = vec![
            1,
            0,
            0,
            15,
            172,
            4,
            1,
            0,
            0,
            15,
            172,
            4,
            akms.len() as u8,
            0,
        ];
        for a in akms {
            value.extend([0, 15, 172, *a]);
        }
        if let Some(c) = caps {
            value.extend(c.to_le_bytes());
        }
        let mut ie = vec![48, value.len() as u8];
        ie.extend(value);
        ie
    }
    #[test]
    fn parses_transition_pmf_and_rsnxe_without_inventing_defaults() {
        let mut ies = rsn(&[2, 8], Some(0x80));
        ies.extend([244, 1, 0x60]);
        let a = parse(&ies, true).unwrap();
        let p = a.rsn.unwrap();
        assert_eq!(p.pmf, "optional");
        assert_eq!(p.akm_suites[1].name, "SAE");
        assert!(a.observations.contains(&"sae_psk_transition_advertised"));
        let x = a.rsnxe.unwrap();
        assert!(x.sae_h2e && x.sae_pk);
        assert_eq!(
            parse(&rsn(&[8], Some(0xc0)), true)
                .unwrap()
                .rsn
                .unwrap()
                .pmf,
            "required"
        );
        assert_eq!(
            parse(&rsn(&[18], None), true).unwrap().rsn.unwrap().pmf,
            "unknown"
        );
        let omitted = parse(&[48, 2, 1, 0], true).unwrap().rsn.unwrap();
        assert!(!omitted.explicit_core_fields);
        assert!(omitted.group_cipher.is_none());
    }
    #[test]
    fn unknown_and_legacy_selectors_are_preserved() {
        let a = parse(&rsn(&[255], Some(0)), true).unwrap();
        assert_eq!(a.rsn.unwrap().akm_suites[0].selector, "000facff");
        assert!(a.observations.contains(&"unknown_akm_selector"));
        let wpa = [
            221, 22, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2,
        ];
        let a = parse(&wpa, true).unwrap();
        assert_eq!(a.wpa.unwrap().pairwise_ciphers[0].name, "TKIP");
        assert!(a.observations.contains(&"legacy_cipher_advertised"));
        assert_eq!(
            parse(&[], false).unwrap().observations,
            ["open_advertisement"]
        );
        assert_eq!(
            parse(&[], true).unwrap().observations,
            ["privacy_without_rsn_or_wpa"]
        );
    }
    fn finding(a: &AdvertisedSecurity, id: &str) -> bool {
        a.assessment.findings.iter().any(|f| f.id == id)
    }
    #[test]
    fn recommendations_distinguish_transition_and_unknown_pmf() {
        let a = parse(&rsn(&[2, 8], Some(0x80)), true).unwrap();
        assert_eq!(a.assessment.advertised_mode, "sae_psk_transition");
        assert!(finding(&a, "sae_psk_transition"));
        assert!(!finding(&a, "modern_akm_pmf_optional"));
        let a = parse(&rsn(&[8], Some(0x80)), true).unwrap();
        assert!(finding(&a, "modern_akm_pmf_optional"));
        let a = parse(&rsn(&[8], Some(0xc0)), true).unwrap();
        assert!(!finding(&a, "modern_akm_pmf_optional"));
        assert!(!finding(&a, "modern_akm_without_pmf_capability"));
        let a = parse(&rsn(&[8], Some(0)), true).unwrap();
        assert!(finding(&a, "modern_akm_without_pmf_capability"));
        let a = parse(&rsn(&[8], Some(0x40)), true).unwrap();
        assert!(finding(&a, "pmf_bits_inconsistent"));
        let a = parse(&rsn(&[8], None), true).unwrap();
        assert!(finding(&a, "rsn_details_unknown"));
        assert!(!finding(&a, "modern_akm_without_pmf_capability"));
        let a = parse(&rsn(&[255], Some(0xc0)), true).unwrap();
        assert!(finding(&a, "unknown_suite"));
    }
    #[test]
    fn owe_audit_preserves_transition_pointer_and_unauthenticated_scope() {
        let mut ies = rsn(&[18], Some(0xc0));
        ies.extend([
            221, 14, 0x50, 0x6f, 0x9a, 0x1c, 2, 1, 2, 3, 4, 5, 3, b'o', b'w', b'e',
        ]);
        let a = parse(&ies, true).unwrap();
        assert_eq!(a.assessment.advertised_mode, "owe_advertised");
        assert!(finding(&a, "owe_transition_advertised"));
        assert!(finding(&a, "owe_no_peer_authentication"));
        assert_eq!(a.owe_transition.as_ref().unwrap().peer_ssid_hex, "6f7765");
        let open = parse(&ies[22..], false).unwrap();
        assert!(finding(&open, "owe_transition_advertised"));
        assert!(!finding(&open, "owe_no_peer_authentication"));
        assert!(!finding(&open, "open_bss"));
        assert!(parse(
            &[221, 11, 0x50, 0x6f, 0x9a, 0x1c, 2, 1, 2, 3, 4, 5, 5],
            false
        )
        .is_err());
    }
    #[test]
    fn malformed_and_duplicate_ies_do_not_become_open_networks() {
        let mut bad = rsn(&[2], Some(0));
        bad[8] = 2;
        assert!(parse(&bad, true).is_err());
        let mut dup = rsn(&[2], None);
        dup.extend(rsn(&[8], None));
        assert!(parse(&dup, true).is_err());
        assert!(parse(&[244, 1, 1], true).is_err());
        assert!(parse(&[48, 4, 1, 0, 0], true).is_err());
    }
}
