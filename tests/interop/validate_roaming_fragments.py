#!/usr/bin/env python3
"""Release acceptance for public FT/SAE-PMK and fragment vectors, no radio.

Checks exact Ethernet payloads, selected timestamps, success/error and absence of
partial plaintext on negative fixtures. Not a claim of passive SAE password recovery.
"""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
from compare_airdecap_ng import packets
ROOT=Path(__file__).resolve().parents[2];FIX=ROOT/'tests/fixtures'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rust',type=Path,required=True);p.add_argument('--report',type=Path,required=True);args=p.parse_args();binary=args.rust.resolve(strict=True)
    normal=json.loads((FIX/'decap-expected.json').read_text());advanced=json.loads((FIX/'advanced-vectors.json').read_text());roaming=json.loads((FIX/'roaming-vectors.json').read_text())
    password=['-e','Test Network','-p','correct horse battery'];pmk=['--pmk',roaming['sae_pmk']]
    unicast=normal['ethernet_from_ap'];group=advanced['group_ethernet']
    cases=[('decap-ft-psk',password,[unicast,group],None),('decap-ft-sae',['-e','Test Network',*pmk],[unicast,group],None),('decap-sae-pmk',pmk,[unicast],None),('decap-sae-gtk',pmk,[group],None),('decap-frag-open',[],[unicast],124),('decap-frag-ccmp',password,[unicast],126),('decap-frag-ccmp-reordered',password,[unicast],127),('decap-frag-tkip',password,[unicast],126),('decap-frag-wep',['--wep-key','0102030405'],[unicast],124)]
    for name in ('decap-frag-ccmp-missing','decap-frag-ccmp-pn-gap','decap-frag-ccmp-conflict','decap-frag-ccmp-expired','decap-frag-ccmp-bad-tag','decap-frag-tkip-bad-michael','decap-ft-psk-bad-mic'):
        cases.append((name,password,[],None))
    rows=[];failures=[]
    with tempfile.TemporaryDirectory(prefix='roaming-fragments-')as tmp:
        for index,(name,extra,expected,time)in enumerate(cases):
            source=FIX/(name+'.pcap');output=Path(tmp)/str(index)
            command=[str(binary),'airdecap','--input',str(source),'--output',str(output),*extra]
            result=subprocess.run(command,capture_output=True,text=True,timeout=30)
            data=packets(output)if output.exists()else[]
            ok=result.returncode==(0 if expected else 1)and[p['data']for p in data]==expected
            if time is not None:ok=ok and data[0]['timestamp_ns']==time*10**9+456000
            if not expected:ok=ok and not output.exists()
            if not ok:failures.append(name)
            rows.append({'capture':name,'sha256':digest(source),'command':command,'exit_code':result.returncode,'packets':data,'ok':ok,'output':result.stdout+result.stderr});print(name,'PASS'if ok else 'FAIL')
    report={'schema_version':1,'rust_sha256':digest(binary),'scope':'synthetic FT personal AKMs, exported SAE PMK, bounded unicast fragment assembly only; no hardware/PAKE qualification','cases':rows,'failures':failures}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
    if failures:raise SystemExit('Failed: '+', '.join(failures))
    print(f'PASS: {len(rows)} roaming/fragment cases')
if __name__=='__main__':main()
