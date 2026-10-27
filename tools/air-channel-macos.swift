// Build beside the CLI: swiftc tools/air-channel-macos.swift -framework CoreWLAN -o target/release/air-channel-macos
// No scans, disassociation, association, or power changes.
import Foundation
import CoreWLAN

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}
let args = CommandLine.arguments
if args.count < 3 { fail("usage: air-channel-macos <interface> info|set [channel]") }
guard let iface = CWWiFiClient.shared().interface(withName: args[1]) else { fail("interface unavailable") }
let supported = (iface.supportedWLANChannels() ?? []).filter {
    ($0.channelBand == .band2GHz || $0.channelBand == .band5GHz) && $0.channelWidth == .width20MHz
}
switch args[2] {
case "info":
    print("power \(iface.powerOn() ? "on" : "off")")
    print("mode \(iface.interfaceMode().rawValue)")
    if let current = iface.wlanChannel() { print("width \(current.channelWidth.rawValue)") }
    if let current = iface.wlanChannel(), current.channelBand == .band2GHz || current.channelBand == .band5GHz {
        print("current \(current.channelNumber)")
    }
    for c in supported.sorted(by: { $0.channelNumber < $1.channelNumber }) { print("channel \(c.channelNumber)") }
case "set":
    guard args.count == 4, let number = Int(args[3]), let channel = supported.first(where: { $0.channelNumber == number }) else { fail("unsupported channel") }
    // Holding the current channel must not attempt to change its width or disrupt association.
    if iface.wlanChannel()?.channelNumber == number {
        print("current \(number)")
        print("changed false")
        exit(0)
    }
    guard iface.interfaceMode() != .station else {
        fail("interface is associated (station mode); channel tuning requires explicit disconnection")
    }
    // Never disconnect the user to make tuning succeed.
    do { try iface.setWLANChannel(channel) } catch {
        let e = error as NSError
        fail("CoreWLAN domain=\(e.domain) code=\(e.code): \(e.localizedDescription); mode=\(iface.interfaceMode().rawValue), power=\(iface.powerOn()), channel=\(iface.wlanChannel()?.channelNumber ?? 0)")
    }
    guard iface.wlanChannel()?.channelNumber == number else {
        fail("CoreWLAN returned success but channel readback did not match \(number)")
    }
    print("current \(number)")
    print("changed true")
default: fail("unknown operation")
}
