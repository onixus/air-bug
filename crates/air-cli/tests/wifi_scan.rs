use std::process::Command;
#[test]
fn ordinary_scan_has_no_monitor_or_channel_options() {
    let cli = env!("CARGO_BIN_EXE_aircrack");
    let output = Command::new(cli).args(["scan", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--cached",
        "--watch",
        "--request-location",
        "--tui",
        "--plain",
        "--ssid",
    ] {
        assert!(help.contains(flag));
    }
    for args in [
        vec!["scan", "--monitor"],
        vec!["scan", "--tui", "--plain"],
        vec!["scan", "--channel", "6"],
        vec!["scan", "--interval", "0"],
        vec![
            "scan",
            "--cached",
            "--request-location",
            "--tui",
            "--plain",
            "--ssid",
        ],
    ] {
        assert!(!Command::new(cli)
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    }
}

#[test]
fn interactive_scan_rejects_non_terminal_before_accessing_wifi() {
    let output = Command::new(env!("CARGO_BIN_EXE_aircrack"))
        .args(["scan", "--tui"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a terminal"));
}
