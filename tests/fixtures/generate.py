"""Deterministic synthetic WPA2-PSK fixtures, generated independently of Rust.

Only Python stdlib hashlib/hmac/struct are used. No live captures or real keys.
Run: python3 tests/fixtures/generate.py
"""
from pathlib import Path
import hashlib
import hmac
import struct

ROOT = Path(__file__).resolve().parent
SSID = b'Test Network'
PASSWORD = b'correct horse battery'
AP = bytes.fromhex('020000000001')
STA = bytes.fromhex('020000000002')
ANONCE = bytes(range(1, 33))
SNONCE = bytes(range(33, 65))
LLC = bytes.fromhex('aaaa03000000888e')
RSN = bytes.fromhex('0100000fac040100000fac040100000fac020000')
PMK = hashlib.pbkdf2_hmac('sha1', PASSWORD, SSID, 4096, 32)
context = min(AP, STA) + max(AP, STA) + min(ANONCE, SNONCE) + max(ANONCE, SNONCE)
PTK = b''.join(hmac.digest(PMK, b'Pairwise key expansion\0' + context + bytes([i]), 'sha1') for i in range(3))[:48]


def key(info, nonce, data=b'', replay=7):
    body = (b'\x02' + struct.pack('!HHQ', info, 16, replay) + nonce
            + bytes(16 + 8 + 8 + 16) + struct.pack('!H', len(data)) + data)
    return b'\x02\x03' + struct.pack('!H', len(body)) + body


M1 = key(0x008a, ANONCE)
M2_ZERO = key(0x010a, SNONCE, bytes([48, len(RSN)]) + RSN)
MIC = hmac.digest(PTK[:16], M2_ZERO, 'sha1')[:16]
M2 = M2_ZERO[:81] + MIC + M2_ZERO[97:]


def dot11(fc, receiver, sender, bssid, payload):
    header = struct.pack('<HH', fc, 0) + receiver + sender + bssid + bytes(2)
    if fc & 0x80 and fc & 0x0c == 8:
        header += bytes(2)  # QoS control
    return header + payload


BEACON = dot11(0x80, bytes([255]) * 6, AP, AP, bytes(12) + bytes([0, len(SSID)]) + SSID)
F1 = dot11(0x0208, STA, AP, AP, LLC + M1)
F2 = dot11(0x0188, AP, STA, AP, LLC + M2)  # QoS to-DS
# A malformed packet and unrelated ordinary data must not produce a handshake.
NOISE = dot11(0x0108, AP, STA, AP, bytes(100))
FRAMES = [b'\x00', BEACON, F1, NOISE, F2, F1]  # retransmission


def pcap(dlt, frames):
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt)
    for frame in frames:
        out += struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame
    return out


def radiotap(frame):
    if len(frame) >= 26 and frame[0] == 0x88:
        frame = frame[:26] + bytes(2) + frame[26:]  # radiotap DATA_PAD
    return struct.pack('<BBHI', 0, 0, 9, 2) + b'\x30' + frame + bytes(4)  # FCS present


def block(kind, payload):
    payload += bytes((-len(payload)) % 4)
    length = 12 + len(payload)
    return struct.pack('<II', kind, length) + payload + struct.pack('<I', length)


def section():
    return block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))


def interface(dlt):
    return block(1, struct.pack('<HHI', dlt, 0, 65535))


def epb(index, frame):
    return block(6, struct.pack('<IIIII', index, 0, 0, len(frame), len(frame)) + frame)


(ROOT / 'wpa2-raw.pcap').write_bytes(pcap(105, FRAMES))
(ROOT / 'wpa2-radiotap.pcap').write_bytes(pcap(127, [radiotap(f) for f in FRAMES]))
ETH = [STA + AP + b'\x88\x8e' + M1, AP + STA + b'\x88\x8e' + M2 + bytes(8)]
(ROOT / 'wpa2-ethernet.pcap').write_bytes(pcap(1, ETH))
# A new section resets interface IDs: ID 0 changes from raw to radiotap.
ng = section() + interface(105) + epb(0, BEACON)
ng += section() + interface(127) + interface(105)
ng += epb(0, radiotap(F1)) + epb(1, NOISE) + epb(0, radiotap(F2))
(ROOT / 'wpa2-mixed.pcapng').write_bytes(ng)
# Simple Packet Block includes alignment padding which must not enter the MIC.
spb = section() + interface(105)
for f in [BEACON, F1, F2]:
    spb += block(3, struct.pack('<I', len(f)) + f)
(ROOT / 'wpa2-simple.pcapng').write_bytes(spb)
(ROOT / 'words.txt').write_text('incorrect password\ncorrect horse battery\nanother wrong password\n')
(ROOT / 'wrong-words.txt').write_text('incorrect password\nanother wrong password\n')
(ROOT / 'vectors.txt').write_text('\n'.join(f'{k}={v.hex()}' for k, v in [('pmk', PMK), ('ptk', PTK), ('mic', MIC), ('eapol_zero', M2_ZERO)]) + '\n')
print('PMK:', PMK.hex(), '\nPTK:', PTK.hex(), '\nMIC:', MIC.hex())

# PMKID has no terminating NUL in its label, and MACs are ordered AP then STA.
PMKID = hmac.digest(PMK, b'PMK Name' + AP + STA, 'sha1')[:16]
KDE = bytes([221, 20]) + bytes.fromhex('000fac04') + PMKID
M1_PMKID = key(0x008a, ANONCE, KDE)
F_PMKID = dot11(0x0208, STA, AP, AP, LLC + M1_PMKID)
# A signed M3 with a synthetic opaque encrypted-key-data block. Verification
# intentionally authenticates M2, so no GTK unwrap/decryption is required.
M3_ZERO = key(0x13ca, ANONCE, bytes(range(24)), replay=8)
M3_MIC = hmac.digest(PTK[:16], M3_ZERO, 'sha1')[:16]
M3 = M3_ZERO[:81] + M3_MIC + M3_ZERO[97:]
F3 = dot11(0x0208, STA, AP, AP, LLC + M3)
# Add an RSN IE to beacon: upstream classifies the network using it.
BEACON_RSN = BEACON + bytes([48, len(RSN)]) + RSN
M2M3_FRAMES = [BEACON_RSN, F2, F3]
PMKID_FRAMES = [BEACON_RSN, F_PMKID]
# Association-request PMKID list is supported independently of EAPOL M1.
RSN_PMKID = RSN + bytes([1, 0]) + PMKID
ASSOC = dot11(0x0000, AP, STA, AP, bytes(4) + bytes([0,len(SSID)]) + SSID + bytes([48,len(RSN_PMKID)]) + RSN_PMKID)
REASSOC = dot11(0x0020, AP, STA, AP, bytes(4) + AP + bytes([48,len(RSN_PMKID)]) + RSN_PMKID)
for stem, frames in [('wpa2-m2m3', M2M3_FRAMES), ('wpa2-pmkid', PMKID_FRAMES),
                     ('wpa2-pmkid-assoc', [BEACON_RSN, ASSOC]),
                     ('wpa2-pmkid-reassoc', [BEACON_RSN, REASSOC])]:
    (ROOT / f'{stem}.pcap').write_bytes(pcap(105, frames))
    (ROOT / f'{stem}-radiotap.pcap').write_bytes(pcap(127, [radiotap(f) for f in frames]))
    (ROOT / f'{stem}.pcapng').write_bytes(section() + interface(105) + b''.join(epb(0,f) for f in frames))
(ROOT / 'wpa2-m2m3-ethernet.pcap').write_bytes(pcap(1, [AP + STA + b'\x88\x8e' + M2, STA + AP + b'\x88\x8e' + M3]))
(ROOT / 'wpa2-pmkid-ethernet.pcap').write_bytes(pcap(1, [STA + AP + b'\x88\x8e' + M1_PMKID]))
# Stable negative fixtures for differential testing; parsing and cryptographic
# mismatch are distinct outcomes and must not be conflated with process failure.
BAD_M2 = M2[:81] + bytes([M2[81] ^ 1]) + M2[82:]
BAD_PMKID = PMKID[:1] + bytes([PMKID[1] ^ 1]) + PMKID[2:]
BAD_KDE = bytes([221,20]) + bytes.fromhex('000fac04') + BAD_PMKID
(ROOT / 'wpa2-m2m3-bad-mic.pcap').write_bytes(pcap(105, [BEACON_RSN, dot11(0x0188, AP, STA, AP, LLC + BAD_M2), F3]))
(ROOT / 'wpa2-pmkid-bad-id.pcap').write_bytes(pcap(105, [BEACON_RSN, dot11(0x0208, STA, AP, AP, LLC + key(0x008a, ANONCE, BAD_KDE))]))
(ROOT / 'wpa2-m1m2-compat.pcap').write_bytes(pcap(105, [BEACON_RSN, F1, F2]))
(ROOT / 'pmkid-vector.txt').write_text(PMKID.hex() + '\n')
print('PMKID:', PMKID.hex())
