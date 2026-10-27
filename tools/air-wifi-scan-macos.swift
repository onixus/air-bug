// Build with tools/build-wifi-scan-macos.sh (bundled identity for Location Services).
// Deliberately separate from channel control. Never opens BPF or changes association,
// channel, power or interface mode. The OS manages an ordinary Wi-Fi scan.
import Foundation
import CoreWLAN
import CoreLocation
import AppKit

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8)); exit(1)
}
struct Network: Encodable {
    let ssid_hex: String?
    let bssid: String?
    let channel: Int?
    let band: Int?
    let signal_dbm: Int?
    let noise_dbm: Int?
    let security: [String]
}
struct Snapshot: Encodable {
    let version = 1
    let source: String
    let mode_before: Int
    let mode_after: Int
    let current_bssid: String?
    let total: Int
    let networks: [Network]
}
let args = CommandLine.arguments
guard (args.count == 3 || (args.count == 4 && args[3] == "--request-location")), ["scan", "cache"].contains(args[2]) else {
    fail("usage: air-wifi-scan-macos <interface> scan|cache [--request-location]")
}
// Establish the bundled app and authorization context on every invocation,
// including cache/watch subprocesses. Initialization does not request consent or
// location coordinates. Only the explicit option below may display a prompt.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let manager = CLLocationManager()
class Delegate: NSObject, CLLocationManagerDelegate {
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {}
}
let delegate = Delegate()
manager.delegate = delegate
_ = manager.authorizationStatus
RunLoop.current.run(until: Date().addingTimeInterval(0.1))
if args.count == 4 {
    guard Bundle.main.bundleURL.pathExtension == "app" else { fail("build the Air Wi-Fi Scan.app companion to request location consent") }
    guard CLLocationManager.locationServicesEnabled() else { fail("Location Services is disabled in macOS System Settings") }
    if manager.authorizationStatus == .notDetermined {
        app.activate(ignoringOtherApps: true)
        manager.requestWhenInUseAuthorization()
        let deadline = Date().addingTimeInterval(45)
        while manager.authorizationStatus == .notDetermined && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
    }
    guard manager.authorizationStatus == .authorizedAlways else {
        fail("Location access was not granted; allow Air Wi-Fi Scan in System Settings > Privacy & Security > Location Services, or run without --request-location for restricted results")
    }
}
guard let iface = CWWiFiClient.shared().interface(withName: args[1]) else { fail("Wi-Fi interface unavailable (check interface name and sandbox access)") }
guard iface.powerOn() else { fail("Wi-Fi is off; no settings changed") }
let before = iface.interfaceMode().rawValue
let results: Set<CWNetwork>
do {
    if args[2] == "cache" {
        guard let cached = iface.cachedScanResults() else { fail("CoreWLAN scan cache is unavailable") }
        results = cached
    } else {
        results = try iface.scanForNetworks(withSSID: nil, includeHidden: true)
    }
} catch {
    let e = error as NSError
    fail("CoreWLAN scan failed: domain=\(e.domain) code=\(e.code): \(e.localizedDescription)")
}
// Report advertised capabilities, including transition/mixed networks.
func security(_ n: CWNetwork) -> [String] {
    var types: [String] = []
    if n.supportsSecurity(.none) { types.append("Open") }
    if n.supportsSecurity(.WEP) || n.supportsSecurity(.dynamicWEP) { types.append("WEP") }
    // Query individual modes: mixed/transition queries can also match a single mode.
    if n.supportsSecurity(.wpaPersonal) || n.supportsSecurity(.wpaEnterprise) { types.append("WPA") }
    if n.supportsSecurity(.wpa2Personal) || n.supportsSecurity(.wpa2Enterprise) { types.append("WPA2") }
    if n.supportsSecurity(.wpa3Personal) || n.supportsSecurity(.wpa3Enterprise) { types.append("WPA3") }
    if n.supportsSecurity(.OWE) { types.append("OWE") }
    return types
}
let after = iface.interfaceMode().rawValue
let currentBSSID = after == 1 ? iface.bssid() : nil
let networks = results.sorted { $0.rssiValue > $1.rssiValue }.prefix(4096).map { n in
    Network(ssid_hex: n.ssidData?.map { String(format: "%02x", $0) }.joined(),
            bssid: n.bssid, channel: n.wlanChannel?.channelNumber,
            band: n.wlanChannel?.channelBand.rawValue,
            signal_dbm: (-127 ..< 0).contains(n.rssiValue) ? n.rssiValue : nil,
            noise_dbm: (-127 ..< 0).contains(n.noiseMeasurement) ? n.noiseMeasurement : nil,
            security: security(n))
}
do {
    let data = try JSONEncoder().encode(Snapshot(source: args[2], mode_before: before,
        mode_after: after, current_bssid: currentBSSID, total: results.count, networks: networks))
    FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
} catch { fail("cannot encode scan results: \(error)") }
