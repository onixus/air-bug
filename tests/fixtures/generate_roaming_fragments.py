"""Independent FT-PSK/FT-SAE, exported-SAE-PMK and fragment fixtures.

All key material is public synthetic data. Python stdlib and OpenSSL are used;
there is no radio, Rust invocation, SAE password attack or private real capture.
"""
import generate_advanced as a
import hashlib,hmac,struct,json
b=a.b;ROOT=a.ROOT;AP=a.AP;STA=a.STA;OTHER=a.OTHER;PLAIN=a.PLAIN
SAE_PMK=hashlib.sha256(b'public synthetic exported SAE PMK').digest()
MDID=b'\x12\x34';R0KH=b'public-r0kh';R1KH=bytes.fromhex('020000000099')
def kdf(key,label,data,n):return b''.join(hmac.digest(key,struct.pack('<H',i)+label+data+struct.pack('<H',n*8),'sha256')for i in range(1,(n+31)//32+1))[:n]
def rsn(akm,name=None):
    body=bytes.fromhex('0100000fac040100000fac040100000fac')+bytes([akm])+bytes(2)
    if name is not None:body+=b'\x01\x00'+name
    return bytes([48,len(body)])+body

def ft_context(pmk):
    r0=kdf(pmk,b'FT-R0',bytes([len(b.SSID)])+b.SSID+MDID+bytes([len(R0KH)])+R0KH+STA,48)
    n0=hashlib.sha256(b'FT-R0N'+r0[32:]).digest()[:16]
    r1=kdf(r0[:32],b'FT-R1',R1KH+STA,32);n1=hashlib.sha256(b'FT-R1N'+n0+R1KH+STA).digest()[:16]
    ptk=kdf(r1,b'FT-PTK',b.SN+b.AN+AP+STA,48)+bytes(16)
    return ptk,n1,r0[:32],r1

def ft_frame(akm,pmk,response=True,gtk=None):
    ptk,name,_,_=ft_context(pmk);rsnie=rsn(akm,name);mdie=bytes([54,3])+MDID+b'\x00'
    sub=bytes([1,6])+R1KH+bytes([3,len(R0KH)])+R0KH
    if gtk is not None:
        g=bytes([1,0,len(gtk)])+bytes(8)+a.wrap(ptk[16:32],gtk);sub+=bytes([2,len(g)])+g
    body=bytes([0,3])+bytes(16)+b.AN+b.SN+sub;ftie=bytes([55,len(body)])+body
    seq=6 if response else 5;mic=a.cmac(ptk[:16],STA+AP+bytes([seq])+rsnie+mdie+ftie)
    ftie=ftie[:4]+mic+ftie[20:]
    if response:frame=b.dot(0x30,STA,AP,AP,bytes(6)+rsnie+mdie+ftie)
    else:frame=b.dot(0x20,AP,STA,AP,bytes(4)+OTHER+rsnie+mdie+ftie)
    return b.beacon+rsn(akm)+mdie,frame,ptk

for name,akm,pmk in [('ft-psk',4,b.PMK),('ft-sae',9,SAE_PMK)]:
    beacon,resp,ptk=ft_frame(akm,pmk,gtk=bytes(range(16)))
    _,request,_=ft_frame(akm,pmk,response=False)
    a.save(name,[beacon,resp]);a.save(name+'-request',[beacon,request])
    data=a.ccmp(b.dot(0x4288,STA,AP,OTHER,tid=5),1,ptk[32:48]);group=a.ccmp(b.dot(0x4288,a.GROUP,AP,OTHER,tid=5),2,bytes(range(16)),1)
    a.save('decap-'+name,[beacon,resp,data,group])
    wrong=bytearray(resp)
    # Flip the signed FTIE MIC without changing its structural shape.
    ftpos=24+6+len(rsn(akm,ft_context(pmk)[1]))+5
    wrong[ftpos+4]^=1;a.save('decap-'+name+'-bad-mic',[beacon,bytes(wrong),data])

def sae_key(msg,ptk,data=b''):
    value=a.eapol(msg,ptk,version=0,data=data)
    if msg==1:return value
    zero=value[:81]+bytes(16)+value[97:];return zero[:81]+a.cmac(ptk[:16],zero)+zero[97:]
sae_ptk=kdf(SAE_PMK,b'Pairwise key expansion',b.CTX,48)+bytes(16)
base=[b.beacon+rsn(8),b.dot(0x0208,STA,AP,AP,b.LLC+sae_key(1,sae_ptk)),b.dot(0x0108,AP,STA,AP,b.LLC+sae_key(2,sae_ptk,rsn(8)))]
sae_data=a.ccmp(b.dot(0x4288,STA,AP,OTHER,tid=5),1,sae_ptk[32:48]);a.save('sae-pmk',base);a.save('decap-sae-pmk',base+[sae_data])
gtk=bytes(range(16));kde=bytes([221,22])+bytes.fromhex('000fac01')+bytes([1,0])+gtk
m3=b.dot(0x0208,STA,AP,AP,b.LLC+sae_key(3,sae_ptk,a.wrap(sae_ptk[16:32],rsn(8)+kde)))
a.save('decap-sae-gtk',base+[m3,a.ccmp(b.dot(0x4288,a.GROUP,AP,OTHER,tid=5),2,gtk,1)])
(ROOT/'sae-pmk-words.txt').write_text(SAE_PMK.hex()+'\n')

def header(fc,index,more,sequence=0x123):
    f=bytearray(b.dot(fc|(0x400 if more else 0),STA,AP,OTHER,tid=5));f[22:24]=struct.pack('<H',(sequence<<4)|index);return bytes(f)
def slices(data):return [data[:16],data[16:32],data[32:]]
def ccmp_part(frame,pn,key,body):
    tid=frame[24]&15 if frame[0]&0x80 else 0;nonce=bytes([tid])+frame[10:16]+pn.to_bytes(6,'big')
    aad=bytes([frame[0]&0x8f,frame[1]&0xc7])+frame[4:22]+bytes([frame[22]&15,0])+(bytes([tid,0])if frame[0]&0x80 else b'')
    auth=len(aad).to_bytes(2,'big')+aad;auth+=bytes(-len(auth)%16);blocks=body+bytes(-len(body)%16)
    state=a.aes(key,b'\x59'+nonce+len(body).to_bytes(2,'big'))
    for i in range(0,len(auth+blocks),16):state=a.aes(key,b.xor(state,(auth+blocks)[i:i+16]))
    tag=b.xor(state[:8],a.aes(key,b'\x01'+nonce+bytes(2))[:8])
    ct=b''.join(b.xor(body[i:i+16],a.aes(key,b'\x01'+nonce+(i//16+1).to_bytes(2,'big')))for i in range(0,len(body),16))
    le=pn.to_bytes(6,'little');return frame+le[:2]+b'\x00\x20'+le[2:]+ct+tag
clear=[header(0x208,i,i<2)+part for i,part in enumerate(slices(PLAIN))];a.save('decap-frag-open',[b.beacon]+clear)
ccmp=[ccmp_part(header(0x4288,i,i<2),i+1,b.PTK[32:48],part)for i,part in enumerate(slices(PLAIN))]
a.save('decap-frag-ccmp',b.base+ccmp);a.save('decap-frag-ccmp-reordered',b.base+[ccmp[2],ccmp[0],ccmp[1]])
a.save('decap-frag-ccmp-missing',b.base+[ccmp[0],ccmp[2]])
a.save('decap-frag-ccmp-pn-gap',b.base+[ccmp_part(header(0x4288,i,i<2),i+1 if i<2 else 7,b.PTK[32:48],part)for i,part in enumerate(slices(PLAIN))])
conflict=ccmp_part(header(0x4288,0,True),1,b.PTK[32:48],b'X'*16)
a.save('decap-frag-ccmp-conflict',b.base+[ccmp[0],conflict]+ccmp[1:])
# TKIP is fragmented after appending Michael; ICV is added independently per MPDU.
tbase,tptk,_,_=a.context(version=1,cipher=2,group_cipher=2,wpa1=True)
mic=a.michael(tptk[48:56],STA,OTHER,5,PLAIN);tkip=[]
for i,part in enumerate(slices(PLAIN+mic)):
    le=(i+1).to_bytes(6,'little');iv=bytes([le[1],(le[1]|0x20)&0x7f,le[0],0x20])+le[2:]
    protected=b.rc4(a.seed(tptk[32:48],AP,le),part+struct.pack('<I',b.zlib.crc32(part)))
    tkip.append(header(0x4288,i,i<2)+iv+protected)
a.save('decap-frag-tkip',tbase+tkip)
wep=[]
for i,part in enumerate(slices(PLAIN)):
    iv=bytes([0x12,0x34,i]);protected=b.rc4(iv+bytes.fromhex('0102030405'),part+struct.pack('<I',b.zlib.crc32(part)))
    wep.append(header(0x4208,i,i<2)+iv+b'\x00'+protected)
a.save('decap-frag-wep',[b.beacon]+wep)
# Fragmented EAPOL and FT management input need reconstruction before verification.
f=b.F2 if hasattr(b,'F2')else b.m2
length=26 if f[0]&0x80 else 24
parts=slices(f[length:]);parts=[parts[0],parts[1],parts[2]];frags=[]
for i,part in enumerate(parts):
    hdr=bytearray(f[:length]);hdr[1]=(hdr[1]|4)if i<2 else hdr[1]&~4;hdr[22:24]=struct.pack('<H',0x4560|i);frags.append(bytes(hdr)+part)
a.save('wpa2-fragmented-m2',[b.beacon_rsn,b.m1]+frags)
beacon,resp,_=ft_frame(4,b.PMK);frags=[]
for i,part in enumerate(slices(resp[24:])):
    hdr=bytearray(resp[:24]);hdr[1]=(hdr[1]|4)if i<2 else hdr[1]&~4;hdr[22:24]=struct.pack('<H',0x5670|i);frags.append(bytes(hdr)+part)
a.save('ft-psk-fragmented',[beacon]+frags)
ptk,n1,r0,r1=ft_context(b.PMK)
(ROOT/'roaming-vectors.json').write_text(json.dumps({'sae_pmk':SAE_PMK.hex(),'ft_ptk':ptk[:48].hex(),'pmk_r0':r0.hex(),'pmk_r1':r1.hex(),'pmkr1_name':n1.hex()},indent=2)+'\n')
print('Generated FT, exported-SAE-PMK and authenticated fragment fixtures.')

# All fragments have valid ICV; only the assembled TKIP Michael MIC is wrong.
bad_full=PLAIN+bytes([mic[0]^1])+mic[1:];bad=[]
for i,part in enumerate(slices(bad_full)):
    le=(i+1).to_bytes(6,'little');iv=bytes([le[1],(le[1]|0x20)&0x7f,le[0],0x20])+le[2:]
    bad.append(header(0x4288,i,i<2)+iv+b.rc4(a.seed(tptk[32:48],AP,le),part+struct.pack('<I',b.zlib.crc32(part))))
a.save('decap-frag-tkip-bad-michael',tbase+bad)
# A malformed high-PN fragment must not turn a missing fragment into plaintext.
bad_tag=ccmp[1][:-1]+bytes([ccmp[1][-1]^1]);a.save('decap-frag-ccmp-bad-tag',b.base+[ccmp[0],bad_tag,ccmp[2]])
# Delay one fragment beyond the two-second capture-time assembly window.
raw=bytearray(b.pcap(105,b.base+ccmp));pos=24
for i in range(6):
    length=struct.unpack_from('<I',raw,pos+8)[0]
    if i==5:struct.pack_into('<I',raw,pos,130)
    pos+=16+length
(ROOT/'decap-frag-ccmp-expired.pcap').write_bytes(raw)

# Deliberately choose a known PMK equal to PBKDF2(password) to prove that SAE
# provenance restrictions cannot be replaced by a coincidental MIC match.
ptk=a.derive(True)
fake_sae=[b.beacon+rsn(8),b.dot(0x0208,STA,AP,AP,b.LLC+sae_key(1,ptk)),b.dot(0x0108,AP,STA,AP,b.LLC+sae_key(2,ptk,rsn(8)))]
a.save('sae-pmk-provenance',fake_sae)
beacon,response,_=ft_frame(9,b.PMK);a.save('ft-sae-pmk-provenance',[beacon,response])

# Simple Packet Blocks carry no timestamp; zero is explicit, not invented time.
spb=b.block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+b.block(1,struct.pack('<HHI',105,0,65535))
for frame in b.base+ccmp:spb+=b.block(3,struct.pack('<I',len(frame))+frame)
(ROOT/'decap-frag-ccmp-spb.pcapng').write_bytes(spb)
