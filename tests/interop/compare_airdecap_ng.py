#!/usr/bin/env python3
"""Compare public synthetic Ethernet payloads/timestamps with upstream airdecap-ng 1.7.

No radio, downloads or installations. Padded-Radiotap differences stay explicit.
"""
import argparse, hashlib, json, os, re, struct, subprocess, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT/'tests/fixtures'

def packets(path):
    data=path.read_bytes(); magic=data[:4]
    if magic not in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') or len(data)<24: raise ValueError('unsupported output PCAP')
    dlt=struct.unpack_from('<I',data,20)[0]
    out=[]; pos=24
    while pos<len(data):
        sec,part,size,original=struct.unpack_from('<IIII',data,pos); pos+=16
        if pos+size>len(data): raise ValueError('truncated output')
        out.append({'dlt':dlt,'timestamp_ns':sec*10**9+part*(1 if magic[0]==0x4d else 1000),'data':data[pos:pos+size].hex()}); pos+=size
    return out

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--upstream',type=Path,required=True); ap.add_argument('--rust',type=Path,required=True); ap.add_argument('--report',type=Path,required=True)
    args=ap.parse_args(); up=args.upstream.resolve(strict=True); rust=args.rust.resolve(strict=True)
    version=subprocess.run([str(up),'--help'],capture_output=True,text=True,timeout=15)
    if 'Airdecap-ng 1.7' not in version.stdout+version.stderr: raise SystemExit('Expected executable upstream 1.7')
    cases=[
        ('decap-ccmp.pcap',['-e','Test Network','-p','correct horse battery'],2,2),
        ('decap-ccmp-radiotap-simple.pcap',['-e','Test Network','-p','correct horse battery'],2,2),
        ('decap-wep40.pcap',['-w','0102030405'],1,1),
        ('decap-wep104.pcap',['-w','0102030405060708090a0b0c0d'],1,1),
        ('decap-open.pcap',[],1,1),
        ('decap-ccmp-bad-tag.pcap',['-e','Test Network','-p','correct horse battery'],0,0),
        ('decap-wep40-bad-icv.pcap',['-w','0102030405'],0,0),
        # Upstream 1.7 does not handle this fixture's Radiotap DATA_PAD/FCS layout.
        ('decap-ccmp-radiotap.pcap',['-e','Test Network','-p','correct horse battery'],2,0),
        ('decap-tkip.pcap',['-e','Test Network','-p','correct horse battery'],2,2),
        ('decap-tkip-wpa2.pcap',['-e','Test Network','-p','correct horse battery'],1,1),
        ('decap-tkip-bad-icv.pcap',['-e','Test Network','-p','correct horse battery'],0,0),
        # Original 1.7 checks TKIP ICV but emits this bad-Michael fixture.
        ('decap-tkip-bad-michael.pcap',['-e','Test Network','-p','correct horse battery'],0,1),
        # Upstream airdecap 1.7 does not install these GTKs or derive v3 PTKs.
        ('decap-gtk-ccmp.pcap',['-e','Test Network','-p','correct horse battery'],1,0),
        ('decap-gtk-ccmp-rekey.pcap',['-e','Test Network','-p','correct horse battery'],2,0),
        ('decap-gtk-tkip.pcap',['-e','Test Network','-p','correct horse battery'],1,0),
        ('decap-gtk-wpa1.pcap',['-e','Test Network','-p','correct horse battery'],1,0),
        ('decap-v3.pcap',['-e','Test Network','-p','correct horse battery'],1,0),
        ('decap-gtk-v3.pcap',['-e','Test Network','-p','correct horse battery'],1,0),
    ]
    cases.extend([
        ('decap-m3m4.pcap',['-e','Test Network','-p','correct horse battery'],1,1),
        ('decap-wds-ccmp.pcap',['-e','Test Network','-p','correct horse battery'],3,3),
        ('decap-wds-tkip.pcap',['-e','Test Network','-p','correct horse battery'],2,2),
        ('decap-wds-wep.pcap',['-w','0102030405'],2,2),
        # Upstream 1.7 emits only one direction for this open WDS fixture.
        ('decap-wds-open.pcap',[],2,1),
    ])
    rows=[]; failures=[]
    with tempfile.TemporaryDirectory(prefix='airdecap-interop-') as tmp:
        for index,(name,extra,n_rust,n_up) in enumerate(cases):
            row={'capture':name,'capture_sha256':sha(FIX/name)}
            for impl,binary,expected in [('rust',rust,n_rust),('upstream',up,n_up)]:
                output=Path(tmp)/f'{index}-{impl}.cap'
                command=([str(binary),'airdecap','-i',str(FIX/name)] if impl=='rust' else [str(binary),str(FIX/name)])+['-b','02:00:00:00:00:01','-o',str(output),*extra]
                result=subprocess.run(command,capture_output=True,text=True,timeout=30)
                decoded=packets(output) if output.exists() else []
                # Rust errors when no plaintext is available; upstream writes an empty PCAP.
                accepted_code=1 if impl=='rust' and expected==0 else 0
                if result.returncode!=accepted_code or len(decoded)!=expected: failures.append(f'{name}/{impl}: exit={result.returncode}, packets={len(decoded)}, expected={expected}')
                row[impl]={'exit_code':result.returncode,'packets':decoded,'output':re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',result.stdout+result.stderr),'command':command}
            row['same_packets']=row['rust']['packets']==row['upstream']['packets']
            if n_rust==n_up and not row['same_packets']: failures.append(f'{name}: different payloads/timestamps')
            rows.append(row); print(name, 'rust=',len(row['rust']['packets']),'upstream=',len(row['upstream']['packets']),'same=',row['same_packets'])
    report={'schema_version':1,'upstream_sha256':sha(up),'rust_sha256':sha(rust),'cases':rows,'failures':failures,'scope':'public synthetic correctness only; no performance/radio qualification'}
    args.report.parent.mkdir(parents=True,exist_ok=True); args.report.write_text(json.dumps(report,indent=2)+'\n')
    if failures: raise SystemExit('\n'.join(failures))
    print(f'PASS: {len(rows)} cases; {sum(row["same_packets"] for row in rows)} identical results; expected coverage/integrity differences recorded')
if __name__=='__main__': main()
