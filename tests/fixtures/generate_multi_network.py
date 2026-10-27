"""Independent synthetic multi-BSSID/SSID dictionaries and PMKID captures."""
from pathlib import Path
import hashlib,hmac,json,struct
ROOT=Path(__file__).resolve().parent
LLC=bytes.fromhex('aaaa03000000888e');RSN=bytes.fromhex('0100000fac040100000fac040100000fac020000')
ALPHA=b'first shared password';BETA=b'second different password';GAMMA=b'other shared password'
def dot(fc,ra,ta,ap,payload):return struct.pack('<HH',fc,0)+ra+ta+ap+bytes(2)+payload
def make(index,ssid,password,hidden=False):
    ap=bytes([2,0,0,0x10,0,index]);sta=bytes([2,0,0,0x20,0,index]);nonce=bytes([index])*32
    pmk=hashlib.pbkdf2_hmac('sha1',password,ssid,4096,32);pmkid=hmac.digest(pmk,b'PMK Name'+ap+sta,'sha1')[:16]
    kde=bytes([221,20])+bytes.fromhex('000fac04')+pmkid
    body=b'\x02'+struct.pack('!HHQ',0x8a,16,7)+nonce+bytes(48)+struct.pack('!H',len(kde))+kde
    eapol=b'\x02\x03'+struct.pack('!H',len(body))+body
    advertised=b'' if hidden else ssid
    beacon=dot(0x80,b'\xff'*6,ap,ap,bytes(12)+bytes([0,len(advertised)])+advertised+bytes([48,len(RSN)])+RSN)
    frame=dot(0x208,sta,ap,ap,LLC+eapol)
    return [beacon,frame],{'bssid':':'.join(f'{b:02x}'for b in ap),'ssid_hex':ssid.hex(),'candidate':password.decode()}
def pcap(frames):
    out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,105)
    for i,frame in enumerate(frames):out+=struct.pack('<IIII',100+i,123,len(frame),len(frame))+frame
    return out
rows=[];allframes=[]
for i,ssid,password in [(1,b'Shared Network',ALPHA),(2,b'Shared Network',ALPHA),(3,b'Different Network',BETA),(4,b'Shared Network',GAMMA)]:
    frames,row=make(i,ssid,password);rows.append(row);allframes+=frames
    (ROOT/f'multi-network-{i}.pcap').write_bytes(pcap(frames))
(ROOT/'multi-networks.pcap').write_bytes(pcap(allframes))
(ROOT/'multi-words-1.txt').write_bytes(b'incorrect password\n'+ALPHA) # deliberately no final LF
(ROOT/'multi-words-empty.txt').write_bytes(b'')
(ROOT/'multi-words-2.txt').write_bytes(BETA+b'\r\n'+GAMMA+b'\n')
frames,hidden=make(5,b'\xff\x00X\x1b',ALPHA,True)
(ROOT/'multi-hidden.pcap').write_bytes(pcap(frames))
(ROOT/'multi-ssid-map.json').write_text(json.dumps([{'bssid':hidden['bssid'],'ssid_hex':hidden['ssid_hex']}],indent=2)+'\n')
(ROOT/'multi-networks-expected.json').write_text(json.dumps({'networks':rows,'hidden':hidden},indent=2)+'\n')
