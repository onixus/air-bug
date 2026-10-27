"""Independent public synthetic M3/M4 and four-address WDS captures.
Python stdlib handles protocols; OpenSSL supplies AES/CMAC only. No real radios.
"""
import hashlib, hmac, struct, json
import generate_advanced as a
b=a.b
ROOT=b.ROOT; AP=b.AP; STA=b.STA
DA=b.OTHER; SA=bytes.fromhex('020000000004')

def m4(ptk,version=2,descriptor=2,nonce=b.SN,counter=8):
    body=bytes([descriptor])+struct.pack('!HHQ',0x308|version,0,counter)+nonce+bytes(48)+bytes(2)
    zero=b'\x02\x03'+struct.pack('!H',len(body))+body
    return a.sign(zero,ptk,version)

def flip(data,offset): return data[:offset]+bytes([data[offset]^1])+data[offset+1:]

def save(name,frames): a.save(name,frames)
base,ptk,ie,desc=a.context()
m3=a.eapol(3,ptk,data=b'',encrypted=False)
f3=b.dot(0x208,STA,AP,AP,b.LLC+m3)
f4=b.dot(0x108,AP,STA,AP,b.LLC+m4(ptk))
save('wpa2-m3m4',[base[0],f3,f4]);save('wpa2-m3m4-reordered',[base[0],f4,f3])
save('wpa2-m3m4-bad-mic',[base[0],f3,b.dot(0x108,AP,STA,AP,b.LLC+flip(m4(ptk),81))])
zero=b.dot(0x108,AP,STA,AP,b.LLC+m4(ptk,nonce=bytes(32)))
save('wpa2-m3m4-zero',[base[0],f3,zero])
# Bad M2 MIC, valid M4 with zero nonce: M2 is nonce context, not the MIC target.
bad_m2=base[2][:24]+b.LLC+flip(base[2][32:],81)
save('wpa2-m234-zero',[base[0],bad_m2,f3,zero])
save('wpa2-m234-zero-padded',[base[0],bad_m2+bytes(8),f3,zero])
save('wpa2-m3m4-replay-mismatch',[base[0],f3,b.dot(0x108,AP,STA,AP,b.LLC+m4(ptk,counter=9))])
other=bytes.fromhex('020000000099')
save('wpa2-m3m4-peer-mismatch',[base[0],f3,b.dot(0x108,AP,other,AP,b.LLC+m4(ptk))])
save('wpa2-m3m4-version-mismatch',[base[0],f3,b.dot(0x108,AP,STA,AP,b.LLC+m4(ptk,version=1))])
# Version 3 must retain explicit PSK-SHA256 negotiation from M2.
vbase,vptk,vie,_=a.context(version=3,akm=6)
v3=b.dot(0x208,STA,AP,AP,b.LLC+a.eapol(3,vptk,3,data=b'',encrypted=False))
v4=b.dot(0x108,AP,STA,AP,b.LLC+m4(vptk,3,nonce=bytes(32)))
save('wpa2-v3-m234-zero',[vbase[0],vbase[2][:32]+flip(vbase[2][32:],81),v3,v4])
save('wpa2-v3-m3m4-no-context',[vbase[0],v3,b.dot(0x108,AP,STA,AP,b.LLC+m4(vptk,3))])
# Legacy descriptor v1 with Secure set, and its nonzero M4 SNonce.
tbase,tptk,tie,tdesc=a.context(version=1,cipher=2,group_cipher=2,wpa1=True)
t3=b.dot(0x208,STA,AP,AP,b.LLC+a.eapol(3,tptk,1,254,encrypted=False))
t4=b.dot(0x108,AP,STA,AP,b.LLC+m4(tptk,1,254))
save('wpa1-m3m4',[tbase[0],t3,t4])

def wds(from_ap=True,qos=True,protected=True,seq=0,frag=0,more=False,da=None,sa=None,tid=5):
    fc=0x308|(0x80 if qos else 0)|(0x4000 if protected else 0)|(0x400 if more else 0)
    ra,ta=(STA,AP)if from_ap else(AP,STA)
    da=da if da is not None else DA if from_ap else SA
    sa=sa if sa is not None else SA if from_ap else DA
    return struct.pack('<HH',fc,0)+ra+ta+da+struct.pack('<H',seq<<4|frag)+sa+(bytes([tid,0])if qos else b'')

def ccmp(frame,pn,key,body=b.PLAIN):
    qos=bool(frame[0]&0x80);tid=frame[30]&15 if qos else 0
    nonce=bytes([tid])+frame[10:16]+pn.to_bytes(6,'big')
    aad=bytes([frame[0]&0x8f,frame[1]&0xc7])+frame[4:22]+bytes([frame[22]&15,0])+frame[24:30]+(bytes([tid,0])if qos else b'')
    auth=len(aad).to_bytes(2,'big')+aad;auth+=bytes(-len(auth)%16)
    blocks=body+bytes(-len(body)%16);state=a.aes(key,b'\x59'+nonce+len(body).to_bytes(2,'big'))
    for i in range(0,len(auth+blocks),16):state=a.aes(key,b.xor(state,(auth+blocks)[i:i+16]))
    tag=b.xor(state[:8],a.aes(key,b'\x01'+nonce+bytes(2))[:8])
    ct=b''.join(b.xor(body[i:i+16],a.aes(key,b'\x01'+nonce+(i//16+1).to_bytes(2,'big')))for i in range(0,len(body),16))
    le=pn.to_bytes(6,'little');return frame+le[:2]+b'\x00\x20'+le[2:]+ct+tag

def radio(frame):
    length=(30 if frame[1]&3==3 else 24)+(2 if frame[0]&0x8c==0x88 else 0)
    return bytes.fromhex('000009000200000030')+frame[:length]+bytes(-length%4)+frame[length:]+bytes(4)
wd3=wds(protected=False)+b.LLC+m3
wd4=wds(False,protected=False)+b.LLC+m4(ptk)
save('wds-m3m4',[base[0],wd3,wd4])
save('decap-m3m4',[base[0],f3,f4,a.ccmp(b.dot(0x4288,STA,AP,DA,tid=5),1,ptk[32:48])])
cc=[ccmp(wds(),1,ptk[32:48]),ccmp(wds(False,qos=False),2,ptk[32:48]),ccmp(wds(da=a.GROUP),3,ptk[32:48])]
save('decap-wds-ccmp',base+cc)
save('decap-wds-m3m4',[base[0],wd3,wd4]+cc)
(ROOT/'decap-wds-radiotap.pcap').write_bytes(b.pcap(127,[radio(f)for f in base+cc]))
save('decap-wds-bad-addr4',base+[flip(cc[0],24)])
wrong=bytearray(wds());wrong[10:16]=other
save('decap-wds-wrong-peer',base+[ccmp(bytes(wrong),4,ptk[32:48])])
parts=[b.PLAIN[:16],b.PLAIN[16:32],b.PLAIN[32:]]
fragments=[ccmp(wds(seq=0x123,frag=i,more=i<2),i+1,ptk[32:48],part)for i,part in enumerate(parts)]
save('decap-wds-fragments',base+[fragments[2],fragments[0],fragments[1]])
conflict=ccmp(wds(seq=0x123,frag=1,more=True,sa=other),2,ptk[32:48],parts[1])
save('decap-wds-fragments-address-mix',base+[fragments[0],conflict,fragments[2]])
save('decap-wds-open',[base[0],wds(protected=False)+b.PLAIN,wds(False,protected=False,qos=False)+b.PLAIN])
wep=bytes.fromhex('0102030405');wv=[]
for i in range(2):
    iv=bytes([0x12,0x34,i]);wv.append(wds(not i,qos=not i)+iv+b'\x00'+b.rc4(iv+wep,b.PLAIN+struct.pack('<I',b.zlib.crc32(b.PLAIN))))
save('decap-wds-wep',[base[0]]+wv)
# TKIP Michael binds DA/SA and priority, independent of RA/TA.
def tkip(frame,pn,body):
    le=pn.to_bytes(6,'little');iv=bytes([le[1],(le[1]|0x20)&0x7f,le[0],0x20])+le[2:]
    return frame+iv+b.rc4(a.seed(tptk[32:48],frame[10:16],le),body+struct.pack('<I',b.zlib.crc32(body)))
tframes=[]
for i in range(2):
    hdr=wds(not i,qos=not i);tid=5 if not i else 0
    mic=a.michael(tptk[48:56]if not i else tptk[56:64],hdr[16:22],hdr[24:30],tid,b.PLAIN)
    tframes.append(tkip(hdr,i+1,b.PLAIN+mic))
save('decap-wds-tkip',tbase+tframes)
full=b.PLAIN+a.michael(tptk[48:56],DA,SA,5,b.PLAIN)
chunks=[full[:16],full[16:32],full[32:]]
save('decap-wds-tkip-fragments',tbase+[tkip(wds(seq=0x234,frag=i,more=i<2),i+1,part)for i,part in enumerate(chunks)])
save('decap-wds-tkip-bad-michael',tbase+[tkip(wds(),1,b.PLAIN+bytes(8))])
(ROOT/'m34-wds-expected.json').write_text(json.dumps({'ethernet':[ (DA+SA+b.PLAIN[6:]).hex(),(SA+DA+b.PLAIN[6:]).hex(),(a.GROUP+SA+b.PLAIN[6:]).hex()]},indent=2)+'\n')
print('Generated M3/M4 and WDS fixtures.')

# Contrived SAE PMK equals PBKDF2(password): M4 context must still prohibit
# treating SAE as a passive password check, even with a cryptographic match.
sptk=b''.join(hmac.digest(b.PMK,struct.pack('<H',i)+b'Pairwise key expansion'+b.CTX+struct.pack('<H',384),'sha256')for i in (1,2))[:48]+bytes(16)
sie=bytes([48,20])+bytes.fromhex('0100000fac040100000fac040100000fac080000')
def sae_key(msg,nonce,data=b''):
    body=b'\x02'+struct.pack('!HHQ',{2:0x108,3:0x3c8,4:0x308}[msg],16,7 if msg==2 else 8)+nonce+bytes(48)+struct.pack('!H',len(data))+data
    value=b'\x02\x03'+struct.pack('!H',len(body))+body
    return value[:81]+a.cmac(sptk[:16],value)+value[97:]
s2=sae_key(2,b.SN,sie)
s3=sae_key(3,b.AN)
s4=sae_key(4,bytes(32))
save('sae-m234-provenance',[b.beacon+sie,b.dot(0x108,AP,STA,AP,b.LLC+flip(s2,81)),b.dot(0x208,STA,AP,AP,b.LLC+s3),b.dot(0x108,AP,STA,AP,b.LLC+s4)])
(ROOT/'m34-pmk-words.txt').write_text(b.PMK.hex()+'\n')
