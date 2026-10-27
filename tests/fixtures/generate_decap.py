"""Independent public synthetic WPA1, CCMP and WEP vectors.

Python stdlib builds packet formats, HMAC-MD5, RC4/ICV and RFC 3610 CCM.
Only the AES block primitive comes from the openssl CLI; no Rust code is used.
"""
from pathlib import Path
import hashlib, hmac, struct, subprocess, zlib, json
ROOT = Path(__file__).resolve().parent
AP = bytes.fromhex('020000000001')
STA = bytes.fromhex('020000000002')
OTHER = bytes.fromhex('020000000003')
SSID = b'Test Network'
PASS = b'correct horse battery'
PMK = hashlib.pbkdf2_hmac('sha1', PASS, SSID, 4096, 32)
AN = bytes(range(1,33)); SN = bytes(range(33,65))
CTX = min(AP,STA)+max(AP,STA)+min(AN,SN)+max(AN,SN)
PTK = b''.join(hmac.digest(PMK,b'Pairwise key expansion\0'+CTX+bytes([i]),'sha1') for i in range(3))[:48]
LLC = bytes.fromhex('aaaa03000000888e')
PLAIN = bytes.fromhex('aaaa030000000800') + b'public synthetic decrypted payload'

def dot(fc,a1,a2,a3,payload=b'',tid=0):
    return struct.pack('<HH',fc,0)+a1+a2+a3+bytes(2)+(bytes([tid,0]) if fc & 0x80 and fc & 12 == 8 else b'')+payload

def key(msg, version=2, descriptor=2):
    info = ({1:0x88,2:0x108,3:0x13c8}[msg]) | version
    body = bytes([descriptor])+struct.pack('!HHQ',info,16,8 if msg==3 else 7)+(AN if msg in (1,3) else SN)+bytes(48)+bytes(2)
    value = b'\x02\x03'+struct.pack('!H',len(body))+body
    if msg!=1:
        mic=hmac.digest(PTK[:16],value,'md5' if version==1 else 'sha1')[:16]
        value=value[:81]+mic+value[97:]
    return value

def pcap(dlt,frames):
    out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,dlt)
    for i,f in enumerate(frames): out+=struct.pack('<IIII',123+i,456,len(f),len(f))+f
    return out

def radio(f):
    # DATA_PAD plus FCS; QoS MAC headers are padded to a four-byte boundary.
    if f[0]&0x80 and f[0]&12==8: f=f[:26]+bytes(2)+f[26:]
    return bytes.fromhex('000009000200000030')+f+bytes(4)

def aes(block):
    return subprocess.run(['openssl','enc','-aes-128-ecb','-K',PTK[32:48].hex(),'-nopad'],input=block,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout

def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def ccmp(frame,pn):
    qos=bool(frame[0]&0x80); tid=frame[24]&15 if qos else 0
    nonce=bytes([tid])+frame[10:16]+pn.to_bytes(6,'big')
    aad=bytes([frame[0]&0x8f,frame[1]&0xc7])+frame[4:22]+bytes([frame[22]&15,0])+(bytes([tid,0]) if qos else b'')
    b0=b'\x59'+nonce+len(PLAIN).to_bytes(2,'big')
    auth=len(aad).to_bytes(2,'big')+aad
    auth+=bytes(-len(auth)%16)
    body=PLAIN+bytes(-len(PLAIN)%16)
    state=aes(b0)
    for pos in range(0,len(auth+body),16): state=aes(xor(state,(auth+body)[pos:pos+16]))
    tag=xor(state[:8],aes(b'\x01'+nonce+bytes(2))[:8])
    encrypted=b''
    for pos in range(0,len(PLAIN),16): encrypted+=xor(PLAIN[pos:pos+16],aes(b'\x01'+nonce+(pos//16+1).to_bytes(2,'big')))
    le=pn.to_bytes(6,'little')
    return frame+le[:2]+b'\x00\x20'+le[2:]+encrypted+tag

def rc4(key,data):
    s=list(range(256)); j=0
    for i in range(256): j=(j+s[i]+key[i%len(key)])%256; s[i],s[j]=s[j],s[i]
    i=j=0; out=[]
    for value in data:
        i=(i+1)%256; j=(j+s[i])%256; s[i],s[j]=s[j],s[i]; out.append(value^s[(s[i]+s[j])%256])
    return bytes(out)

beacon=dot(0x80,bytes([255])*6,AP,AP,bytes(12)+bytes([0,len(SSID)])+SSID)
rsn=bytes.fromhex('0100000fac040100000fac040100000fac020000')
beacon_rsn=beacon+bytes([48,len(rsn)])+rsn
m1=dot(0x0208,STA,AP,AP,LLC+key(1)); m2=dot(0x0108,AP,STA,AP,LLC+key(2))
# WPA vendor IE: TKIP group/pairwise and PSK AKM, matching WPA1 descriptor 254.
wpa=bytes.fromhex('0050f20101000050f20201000050f20201000050f202')
wpa1=[beacon+bytes([221,len(wpa)])+wpa,dot(0x0208,STA,AP,AP,LLC+key(1,1,254)),dot(0x0108,AP,STA,AP,LLC+key(2,1,254))]
(ROOT/'wpa1-m1m2.pcap').write_bytes(pcap(105,wpa1))
# Distinct packet numbers, both directions, QoS priority 5 and ordinary data.
data=[ccmp(dot(0x4288,STA,AP,OTHER,tid=5),1),ccmp(dot(0x4108,AP,STA,OTHER),2)]
base=[beacon_rsn,m1,m2]
(ROOT/'decap-ccmp.pcap').write_bytes(pcap(105,base+data))
(ROOT/'decap-ccmp-radiotap.pcap').write_bytes(pcap(127,[radio(f) for f in base+data]))
bad=data[0][:-1]+bytes([data[0][-1]^1])
(ROOT/'decap-ccmp-bad-tag.pcap').write_bytes(pcap(105,base+[bad]))
(ROOT/'decap-ccmp-no-handshake.pcap').write_bytes(pcap(105,[beacon_rsn]+data))
(ROOT/'decap-open.pcap').write_bytes(pcap(105,[beacon,dot(0x0208,STA,AP,OTHER,PLAIN)]))
for secret in [bytes.fromhex('0102030405'),bytes.fromhex('0102030405060708090a0b0c0d')]:
    iv=b'\x12\x34\x56'
    body=rc4(iv+secret,PLAIN+struct.pack('<I',zlib.crc32(PLAIN)))
    frames=[beacon,dot(0x4208,STA,AP,OTHER,iv+b'\x00'+body)]
    (ROOT/f'decap-wep{len(secret)*8}.pcap').write_bytes(pcap(105,frames))
    bad=frames[1][:-1]+bytes([frames[1][-1]^1])
    (ROOT/f'decap-wep{len(secret)*8}-bad-icv.pcap').write_bytes(pcap(105,[beacon,bad]))
(ROOT/'decap-expected.json').write_text(json.dumps({'pmk':PMK.hex(),'payload':PLAIN.hex(),'ethernet_from_ap':(STA+OTHER+PLAIN[6:]).hex(),'ethernet_to_ap':(OTHER+STA+PLAIN[6:]).hex()},indent=2)+'\n')
print('Generated WPA1, CCMP, WEP40/WEP104 and integrity-negative captures (public synthetic keys).')

def block(kind,payload):
    payload+=bytes(-len(payload)%4)
    length=len(payload)+12
    return struct.pack('<II',kind,length)+payload+struct.pack('<I',length)

def ng(frames,resolution=6,offset=0):
    section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    opts=struct.pack('<HH',9,1)+bytes([resolution,0,0,0])+struct.pack('<HHq',14,8,offset)+bytes(4)
    result=section+block(1,struct.pack('<HHI',105,0,65535)+opts)
    for i,f in enumerate(frames):
        ticks=(123+i)*1_000_000+456 if resolution==6 else (123+i)*1024+512
        result+=block(6,struct.pack('<IIIII',0,ticks>>32,ticks&0xffffffff,len(f),len(f))+f)
    return result
(ROOT/'decap-ccmp.pcapng').write_bytes(ng(base+data))
(ROOT/'decap-ccmp-tsresol.pcapng').write_bytes(ng(base+data,128|10,-1))

(ROOT/'decap-ccmp-radiotap-simple.pcap').write_bytes(pcap(127,[bytes.fromhex('0000080000000000')+f for f in base+data]))

(ROOT/'wpa1-m2m3.pcap').write_bytes(pcap(105,[wpa1[0],wpa1[2],dot(0x0208,STA,AP,AP,LLC+key(3,1,254))]))
