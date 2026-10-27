#!/usr/bin/env python3
"""Release acceptance for public multi-input/network/checkpoint fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

FIX=Path(__file__).resolve().parents[1]/'fixtures'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();binary=args.rust.resolve(strict=True)
    caps=[FIX/f'multi-network-{i}.pcap'for i in range(1,5)]
    words=[FIX/n for n in ['multi-words-1.txt','multi-words-empty.txt','multi-words-2.txt']]
    expected=json.loads((FIX/'multi-networks-expected.json').read_text())['networks']
    rows=[]
    with tempfile.TemporaryDirectory(prefix='air-multi-release-')as folder:
        folder=Path(folder);cache=folder/'keys.pmk-cache';session=folder/'session'
        def run(name,extra=(),code=0,captures=caps,dictionaries=words):
            output=folder/f'{name}.json';command=[str(binary),'aircrack']
            for path in captures:command+=['--capture',str(path)]
            for path in dictionaries:command+=['--wordlist',str(path)]
            command+=['--results-json',str(output),'--threads','2',*map(str,extra)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=30)
            data=json.loads(output.read_text())if output.exists()else None
            row={'case':name,'exit_code':result.returncode,'expected_code':code,'results':data,'ok':result.returncode==code}
            rows.append(row)
            return row,result
        def complete(row):
            data=row['results'];row['ok']&=data is not None and data['status']=='complete'
            if data:
                row['ok']&=len(data['networks'])==4 and all(all(got[k]==want[k]for k in ['bssid','ssid_hex','candidate'])for got,want in zip(data['networks'],expected))
        row,result=run('cold-cache',['--pmk-cache',cache,'--pmk-cache-mib','1']);complete(row);row['ok']&='derived=8'in result.stderr
        row,result=run('warm-cache',['--pmk-cache',cache,'--pmk-cache-mib','1']);complete(row);row['ok']&='hits=8 misses=0 derived=0'in result.stderr
        row,_=run('paused',['--session',session,'--max-candidates','2'],code=1)
        row['ok']&=row['results']is not None and row['results']['status']=='paused'and sum(n['status']=='found'for n in row['results']['networks'])==2
        saved=json.loads(session.read_text());row['ok']&=saved['version']==6 and saved['completed_lines']==2 and 'first shared password'not in session.read_text()
        row,_=run('resume',['--resume',session]);complete(row)
        row,_=run('resume-complete',['--resume',session]);complete(row)
        row,result=run('changed-capture-order',['--resume',session],code=1,captures=list(reversed(caps)))
        row['ok']&=row['results']is None and 'input mismatch'in result.stderr
        row,_=run('selected',['--bssid','02:00:00:10:00:01','--max-records','1'])
        row['ok']&=row['results']is not None and row['results']['status']=='complete'and len(row['results']['networks'])==1
        row,_=run('hidden-ssid',['--ssid-map',FIX/'multi-ssid-map.json'],captures=[FIX/'multi-hidden.pcap'],dictionaries=words[:1])
        row['ok']&=row['results']is not None and row['results']['networks'][0]['ssid_hex']=='ff00581b'and row['results']['status']=='complete'
        row,_=run('exhausted',code=1,dictionaries=words[:1])
        row['ok']&=row['results']is not None and row['results']['status']=='exhausted'and sum(n['status']=='found'for n in row['results']['networks'])==2
    failures=[row['case']for row in rows if not row['ok']]
    report={'schema_version':1,'rust_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'scope':'public synthetic multi-input/SSID grouping/checkpoint correctness; no radio qualification','cases':rows,'failures':failures}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
    for row in rows:print(row['case'],'PASS'if row['ok']else'FAIL')
    if failures:raise SystemExit('Failed: '+', '.join(failures))

if __name__=='__main__':main()
