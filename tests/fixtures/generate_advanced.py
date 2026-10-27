"""Public independent TKIP/Michael, GTK/wrap and descriptor-v3 captures.

Python stdlib implements the wire formats/key mixing; OpenSSL supplies AES/CMAC.
All addresses/passwords/keys are synthetic. No radio or Rust code is used.
"""
import generate_decap as b
import hashlib,hmac,struct,json,subprocess
ROOT=b.ROOT; AP=b.AP; STA=b.STA; OTHER=b.OTHER; PMK=b.PMK; PLAIN=b.PLAIN
GROUP=bytes.fromhex('01005e010203')
def aes(key,block):
    return subprocess.run(['openssl','enc','-aes-128-ecb','-K',key.hex(),'-nopad'],input=block,capture_output=True,check=True).stdout
def cmac(key,data):
    return subprocess.run(['openssl','dgst','-mac','cmac','-macopt','cipher:aes-128-cbc','-macopt','hexkey:'+key.hex(),'-binary'],input=data,capture_output=True,check=True).stdout

def derive(sha=False):
    if sha:
        value=b''.join(hmac.digest(PMK,struct.pack('<H',i)+b'Pairwise key expansion'+b.CTX+struct.pack('<H',384),'sha256') for i in (1,2))[:48]
        return value+bytes(16)
    return b''.join(hmac.digest(PMK,b'Pairwise key expansion\0'+b.CTX+bytes([i]),'sha1') for i in range(4))[:64]

def sign(value,ptk,version):
    zero=value[:81]+bytes(16)+value[97:]
    mic=cmac(ptk[:16],zero) if version==3 else hmac.digest(ptk[:16],zero,'md5' if version==1 else 'sha1')[:16]
    return zero[:81]+mic+zero[97:]
def eapol(msg,ptk,version=2,descriptor=2,data=b'',iv=bytes(16),index=0,encrypted=True,counter=None):
    flags={1:0x88,2:0x108,3:0x3c8,5:0x380}[msg]|version
    if msg in (3,5) and encrypted and descriptor==2: flags|=0x1000
    if msg==5 and descriptor==254: flags|=index<<4
    nonce=b.AN if msg in (1,3) else b.SN if msg==2 else bytes([0x77])*32
    counter=counter if counter is not None else 8 if msg in (3,5) else 7
    keylen=len(data) if descriptor==254 and msg==5 else 16
    body=bytes([descriptor])+struct.pack('!HHQ',flags,keylen,counter)+nonce+iv+bytes(8+8+16)+struct.pack('!H',len(data))+data
    value=b'\x02\x03'+struct.pack('!H',len(body))+body
    return sign(value,ptk,version) if msg!=1 else value

def wrap(kek,data):
    if len(data)%8 or len(data)<16: data+=b'\xdd\x00';data+=bytes(-len(data)%8)
    a=b'\xa6'*8;blocks=[data[i:i+8] for i in range(0,len(data),8)]
    for j in range(6):
        for i in range(len(blocks)):
            value=aes(kek,a+blocks[i]);a=(int.from_bytes(value[:8],'big')^(len(blocks)*j+i+1)).to_bytes(8,'big');blocks[i]=value[8:]
    return a+b''.join(blocks)

def ccmp(frame,pn,key,keyid=0):
    tid=frame[24]&15 if frame[0]&0x80 else 0
    nonce=bytes([tid])+frame[10:16]+pn.to_bytes(6,'big')
    aad=bytes([frame[0]&0x8f,frame[1]&0xc7])+frame[4:22]+bytes([frame[22]&15,0])+(bytes([tid,0]) if frame[0]&0x80 else b'')
    auth=len(aad).to_bytes(2,'big')+aad;auth+=bytes(-len(auth)%16)
    body=PLAIN+bytes(-len(PLAIN)%16)
    state=aes(key,b'\x59'+nonce+len(PLAIN).to_bytes(2,'big'))
    for i in range(0,len(auth+body),16):state=aes(key,b.xor(state,(auth+body)[i:i+16]))
    tag=b.xor(state[:8],aes(key,b'\x01'+nonce+bytes(2))[:8])
    ct=b''.join(b.xor(PLAIN[i:i+16],aes(key,b'\x01'+nonce+(i//16+1).to_bytes(2,'big'))) for i in range(0,len(PLAIN),16))
    le=pn.to_bytes(6,'little');return frame+le[:2]+bytes([0,0x20|keyid<<6])+le[2:]+ct+tag

def multiply(a,c):
    out=0
    while c:
        if c&1:out^=a
        a=((a<<1)^(0x11b if a&128 else 0))&255;c>>=1
    return out
def sbox(i):
    inv=0 if i==0 else 1
    if i:
        for _ in range(254):inv=multiply(inv,i)
    value=inv
    for n in range(1,5):value^=((inv<<n)|(inv>>(8-n)))&255
    value^=0x63;twice=multiply(value,2);return (twice<<8)|(twice^value)
S=[sbox(i) for i in range(256)]
def sub(x):return S[x&255]^int.from_bytes(S[x>>8].to_bytes(2,'little'),'big')
def ror(x,n,bits):return ((x>>n)|(x<<(bits-n)))&((1<<bits)-1)
def seed(tk,ta,pn):
    tk=struct.unpack('<8H',tk);p=list(struct.unpack('<2H',pn[2:])+struct.unpack('<3H',ta))
    for i in range(8):
        j=i%2
        for n,k in enumerate((j,j+2,j+4,j+6,j)):
            p[n]=(p[n]+sub(p[(n-1)%5]^tk[k])+(i if n==4 else 0))&65535
    p.append((p[4]+int.from_bytes(pn[:2],'little'))&65535)
    for i in range(6):p[i]=(p[i]+sub(p[(i-1)%6]^tk[i]))&65535
    for i in range(6):p[i]=(p[i]+ror(p[(i-1)%6]^(tk[i+6] if i<2 else 0),1,16))&65535
    return bytes([pn[1],(pn[1]|0x20)&0x7f,pn[0],((p[5]^tk[0])>>1)&255])+struct.pack('<6H',*p)
def michael(key,dst,src,tid,data):
    l,r=struct.unpack('<2I',key);data=dst+src+bytes([tid,0,0,0])+data+b'\x5a'+bytes(4);data+=bytes(-len(data)%4)
    for (word,)in struct.iter_unpack('<I',data):
        l^=word;r^=ror(l,15,32);l=(l+r)&0xffffffff
        r^=((l&0xff00ff00)>>8)|((l&0xff00ff)<<8);l=(l+r)&0xffffffff
        r^=ror(l,29,32);l=(l+r)&0xffffffff
        r^=ror(l,2,32);l=(l+r)&0xffffffff
    return struct.pack('<2I',l,r)
def tkip(frame,pn,key,mic_key,keyid=0,bad_michael=False):
    tid=frame[24]&15 if frame[0]&0x80 else 0
    dst,src=(frame[16:22],frame[10:16]) if frame[1]&3==1 else (frame[4:10],frame[16:22])
    mic=michael(mic_key,dst,src,tid,PLAIN)
    if bad_michael:mic=bytes([mic[0]^1])+mic[1:]
    data=PLAIN+mic;data+=struct.pack('<I',b.zlib.crc32(data))
    le=pn.to_bytes(6,'little');iv=bytes([le[1],(le[1]|0x20)&0x7f,le[0],0x20|keyid<<6])+le[2:]
    return frame+iv+b.rc4(seed(key,frame[10:16],le),data)

def context(version=2,cipher=4,group_cipher=4,akm=2,wpa1=False):
    ptk=derive(akm==6);rsn=bytes.fromhex('0100000fac')+bytes([group_cipher])+bytes.fromhex('0100000fac')+bytes([cipher])+bytes.fromhex('0100000fac')+bytes([akm])+bytes(2)
    ie=bytes([48,len(rsn)])+rsn;beacon=b.beacon+ie
    desc=254 if wpa1 else 2
    if wpa1:beacon=b.wpa1[0];ie=b''
    frames=[beacon,b.dot(0x0208,STA,AP,AP,b.LLC+eapol(1,ptk,version,desc)),b.dot(0x0108,AP,STA,AP,b.LLC+eapol(2,ptk,version,desc,data=ie))]
    return frames,ptk,ie,desc

def save(name,frames):
    (ROOT/(name+'.pcap')).write_bytes(b.pcap(105,frames))

def delivery(ptk,ie,gtk,index,version=2,desc=2,msg=3,bad_mic=False,bad_wrap=False,bad_kde=False):
    if desc==254:
        iv=bytes(range(16));wrapped=b.rc4(iv+ptk[16:32],bytes(256)+gtk)[256:]
    else:
        key=gtk[:-1] if bad_kde else gtk
        kde=bytes([221,6+len(key)])+bytes.fromhex('000fac01')+bytes([index,0])+key
        wrapped=wrap(ptk[16:32],(ie if msg==3 else b'')+kde);iv=bytes(16)
    if bad_wrap:wrapped=bytes([wrapped[0]^1])+wrapped[1:]
    value=eapol(msg,ptk,version,desc,data=wrapped,iv=iv,index=index)
    if bad_mic:value=value[:81]+bytes([value[81]^1])+value[82:]
    return b.dot(0x0208,STA,AP,AP,b.LLC+value)

base,ptk,ie,desc=context(version=1,cipher=2,group_cipher=2,wpa1=True)
a=tkip(b.dot(0x4288,STA,AP,OTHER,tid=5),1,ptk[32:48],ptk[48:56]);c=tkip(b.dot(0x4108,AP,STA,OTHER),0x102030405,ptk[32:48],ptk[56:64])
save('decap-tkip',base+[a,c]);save('decap-tkip-bad-michael',base+[tkip(b.dot(0x4288,STA,AP,OTHER,tid=5),1,ptk[32:48],ptk[48:56],bad_michael=True)])
bad=a[:-1]+bytes([a[-1]^1]);save('decap-tkip-bad-icv',base+[bad])
base,ptk,ie,desc=context(version=1,cipher=2,group_cipher=2)
save('decap-tkip-wpa2',base+[tkip(b.dot(0x4208,STA,AP,OTHER),0x10000,ptk[32:48],ptk[48:56])])
base,ptk,ie,desc=context(version=3,akm=6)
save('wpa2-v3',base);save('decap-v3',base+[ccmp(b.dot(0x4288,STA,AP,OTHER,tid=5),1,ptk[32:48])])
# V3 M2/M3-only uses a genuine wrapped GTK M3 and derives from M3 ANonce.
gtk=bytes(range(16));m3=delivery(ptk,ie,gtk,1,version=3)
save('wpa2-v3-m2m3',[base[0],base[2],m3]);save('decap-gtk-v3',base+[m3,ccmp(b.dot(0x4288,GROUP,AP,OTHER,tid=5),1,gtk,1)])
for group_cipher,name,version,wpa1 in [(4,'ccmp',2,False),(2,'tkip',2,False),(2,'wpa1',1,True)]:
    base,ptk,ie,desc=context(version=version,group_cipher=group_cipher,wpa1=wpa1)
    gtk=bytes(range(16 if group_cipher==4 else 32));group=b.dot(0x4288,GROUP,AP,OTHER,tid=5)
    data=ccmp(group,1,gtk,1) if group_cipher==4 else tkip(group,1,gtk[:16],gtk[16:24],1)
    msg=5 if wpa1 else 3
    m=delivery(ptk,ie,gtk,1,version,desc,msg)
    save('decap-gtk-'+name,base+[m,data]);save('decap-gtk-'+name+'-missing',base+[data])
    if not wpa1:
        for error in ('bad-mic','bad-wrap','bad-kde'):
            opts={error.replace('-','_'):True}
            save('decap-gtk-'+name+'-'+error,base+[delivery(ptk,ie,gtk,1,version,desc,msg,**opts),data])
        # Separate group rekey G1 and a different key ID, then same-ID reuse.
        second=bytes(x^0x55 for x in gtk)
        later=ccmp(group,2,second,2) if group_cipher==4 else tkip(group,2,second[:16],second[16:24],2)
        save('decap-gtk-'+name+'-rekey',base+[m,data,delivery(ptk,ie,second,2,version,desc,5),later])
(ROOT/'advanced-vectors.json').write_text(json.dumps({'tkip_seed':seed(derive()[32:48],AP,(1).to_bytes(6,'little')).hex(),'ptk_sha256':derive(True)[:48].hex(),'group_ethernet':(GROUP+OTHER+PLAIN[6:]).hex()},indent=2)+'\n')
print('Generated independent TKIP/Michael, authenticated GTK and descriptor-v3 fixtures.')

# Authentic MIC with inconsistent M3 epoch metadata must not install a GTK.
base,ptk,ie,desc=context();gtk=bytes(range(16));group=ccmp(b.dot(0x4288,GROUP,AP,OTHER,tid=5),1,gtk,1)
carrier=delivery(ptk,ie,gtk,1)
for label,offset in [('wrong-nonce',17),('wrong-replay',16)]:
    value=bytearray(carrier[32:]);value[offset]^=1
    save('decap-gtk-ccmp-'+label,base+[carrier[:32]+sign(bytes(value),ptk,2),group])
other_sta=bytearray(carrier);other_sta[9]^=1
save('decap-gtk-ccmp-wrong-peer',base+[bytes(other_sta),group])
# Reuse Key ID 1 with a different key, retaining both historical epochs offline.
second=bytes(x^0x55 for x in gtk)
save('decap-gtk-ccmp-same-id-rekey',base+[carrier,group,delivery(ptk,ie,second,1,msg=5),ccmp(b.dot(0x4288,GROUP,AP,OTHER,tid=5),2,second,1)])
base,ptk,ie,desc=context(version=1,cipher=2,group_cipher=2,wpa1=True);gtk=bytes(range(32))
save('decap-gtk-wpa1-bad-mic',base+[delivery(ptk,ie,gtk,1,1,desc,5,bad_mic=True),tkip(b.dot(0x4208,GROUP,AP,OTHER),1,gtk[:16],gtk[16:24],1)])
# To-DS multicast MSDUs still use the pairwise key (receiver A1 is the AP).
save('decap-tkip-to-ds-multicast',base+[tkip(b.dot(0x4108,AP,STA,GROUP),3,ptk[32:48],ptk[56:64])])
