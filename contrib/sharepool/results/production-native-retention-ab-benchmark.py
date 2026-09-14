#!/usr/bin/env python3
"""Controlled native retention A/B/A on one closed, path-bound regtest fixture.

No mining, payout, profile-marker changes, or external peers. The original node
state is backed up, each arm uses that exact path, and every stopped arm is moved
aside before restoring the byte-identical original backup.
"""
from pathlib import Path
import argparse,base64,hashlib,http.client,json,math,os,shutil,sqlite3,struct,subprocess,sys,time
from datetime import datetime,timezone
from dataclasses import replace


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def tree(path):
    return {str(p.relative_to(path)):sha(p) for p in sorted(path.rglob('*')) if p.is_file()}
def cpu(pid):
    raw=subprocess.check_output(['/bin/ps','-o','time=','-p',str(pid)],text=True).strip()
    parts=raw.split(':');total=0.
    for part in parts: total=60*total+float(part)
    return total

def extract(repo,journal,out):
    sys.path[:0]=[str(repo/'test/functional'),str(repo/'contrib/sharepool')]
    import hash_gate_archive,native_archive
    from hash_snapshot import parse_share
    from hash_mining_gate import HashMiningGate
    from native_mining_gate import immutable_header,parse_block
    conn=sqlite3.connect(journal.as_uri()+'?mode=ro',uri=True)
    config=conn.execute('select value from config').fetchone()[0]
    binding=hashlib.sha256(config).hexdigest();current=native_archive.initial_head(binding)
    trusted=hash_gate_archive.read_head(str(journal)+'.archive-head.json')
    templates={};proofs=[]
    for seq,kind,identity,digest,raw,previous,root,revision,height,parent,size,segment,offset in conn.execute('select * from journal order by sequence'):
        assert segment==offset==0 and len(raw)==size,'This capture requires inline closed journal records'
        assert digest==hashlib.sha256(raw).hexdigest() and previous==current['root']
        expected_revision=current['receipt_revision']+int(kind==2)
        expected_root=hashlib.sha256(b'SharePool/hash-gate/event/v7\0'+bytes.fromhex(current['root'])+struct.pack('<QBQI',current['events']+1,kind,expected_revision,len(raw))+bytes.fromhex(identity)+bytes.fromhex(digest)).hexdigest()
        assert (seq,revision,root)==(current['events']+1,expected_revision,expected_root)
        current=dict(current,events=seq,receipt_revision=revision,root=root,bytes=current['bytes']+hash_gate_archive.RECORD.size+len(raw))
        if kind==1: templates[identity]=(raw,height,parent)
        elif kind==2: proofs.append((raw,height,parent,identity))
    assert current==trusted;conn.close()
    maximum=max(p[1] for p in proofs);selected={}
    for raw,height,parent,identity in proofs:
        if height!=maximum: continue
        proof=parse_share(raw);tid=f'{proof.header_facts.template_id:064x}'
        if tid in selected: continue
        origin,origin_height,origin_parent=templates[tid]
        assert HashMiningGate._describe_uncached(2,raw)==(identity,height,parent)
        assert HashMiningGate._describe_uncached(1,origin)==(tid,origin_height,origin_parent)
        assert immutable_header(parse_block(origin))==proof.header_facts.immutable_header
        selected[tid]={'template_id':tid,'proof_id':identity,'template_hex':origin.hex(),'proof_hex':raw.hex()}
    assert len(selected)==100,len(selected)
    requests=[selected[k] for k in sorted(selected)]
    invalid=bytearray.fromhex(requests[0]['proof_hex']);invalid[-1]^=1
    missing=parse_share(bytes.fromhex(requests[0]['proof_hex']));changed_header=missing.header;changed_header.m_mm_rhs^=1
    missing=replace(missing,header_bytes=changed_header.serialize());assert missing.serialize().hex()!=requests[0]['proof_hex']
    data={'schema':1,'journal':str(journal),'journal_sha256':sha(journal),'protected_head':trusted,'origin_height':maximum,'requests':requests,'controls':[{'label':'changed-authorization','method':'validatesharepoolhashshare','params':[invalid.hex()]},{'label':'unavailable-origin','method':'validatesharepoolhashshare','params':[missing.serialize().hex()]}]}
    (out/'requests.json').write_bytes(canonical(data)+b'\n');return data

class RPC:
    def __init__(self,port,cookie):
        self.conn=http.client.HTTPConnection('127.0.0.1',port,timeout=60)
        self.auth='Basic '+base64.b64encode(cookie).decode();self.id=0
    def call(self,method,*params):
        self.id+=1;body=json.dumps({'jsonrpc':'2.0','id':self.id,'method':method,'params':params})
        self.conn.request('POST','/',body,{'Authorization':self.auth,'Content-Type':'application/json'})
        response=self.conn.getresponse();value=json.loads(response.read())
        if value.get('error'): return {'error':value['error']}
        return {'result':value['result']}
    def result(self,method,*params):
        result=self.call(method,*params);assert 'result' in result,result;return result['result']
    def close(self):self.conn.close()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--source-node',type=Path,required=True);ap.add_argument('--journal',type=Path,required=True);ap.add_argument('--workdir',type=Path,required=True);ap.add_argument('--results',type=Path,required=True);ap.add_argument('--rpcport',type=int,default=26743);args=ap.parse_args()
    repo=args.repo.resolve();node=args.source_node.resolve();out=args.workdir.resolve();out.mkdir(exist_ok=True)
    data=extract(repo,args.journal.resolve(),out)
    marker=node/'regtest/sharepool-profile-v7';marker_before=marker.read_bytes()
    assert ('blocks='+str(node/'regtest/blocks')+'\n').encode() in marker_before
    original=tree(node);backup=out/'original-node0';assert not backup.exists();shutil.copytree(node,backup);assert tree(backup)==original
    report={'schema':1,'result':'running','started_utc':datetime.now(timezone.utc).isoformat(),'command':[sys.executable,*sys.argv],'script_sha256':sha(__file__),'requests_sha256':sha(out/'requests.json'),'request_count':100,'warmup_passes':1,'measured_passes':1,'rpc_threads':1,'order':['on-first','off','on-second'],'profile_marker_sha256':hashlib.sha256(marker_before).hexdigest(),'source_tree_sha256':hashlib.sha256(canonical(original)).hexdigest(),'arms':[],'limitations':['Controlled serial RPC microbenchmark on one retained native tip, not sustained or end-to-end miner throughput.','One RPC worker fixes thread-local history routing; production defaults to16 workers.','One alternating on/off/on sequence, no isolated-host or statistical confidence guarantee.','Only two newly introduced optional decoded-retention routes differ; canonical preparation reuse and job-preparation retention remain enabled.']}
    reference=None;arm_id=None
    def save():args.results.write_text(json.dumps(report,indent=2)+'\n')
    save()
    for arm_id,binary_name in [('on-first','bitcoind-retention-on'),('off','bitcoind-retention-off'),('on-second','bitcoind-retention-on')]:
        assert tree(node)==original and marker.read_bytes()==marker_before
        binary=out/binary_name
        command=[str(binary),'-datadir='+str(node),'-regtest','-sharepoolheight=102','-sharepoolhashonly=1','-sharepooltides=1','-sharepoolcompacttides=1','-testactivationheight=blake2b@1','-disablewallet','-corepolicy','-softwareexpiry=0','-walletimplicitsegwit','-networkactive=0','-maxconnections=0','-connect=0','-rpcthreads=1','-rpcport='+str(args.rpcport),'-rpcbind=127.0.0.1','-printtoconsole=0']
        log=(out/(arm_id+'-process.txt')).open('w');process=subprocess.Popen(command,cwd=repo,stdout=log,stderr=subprocess.STDOUT);rpc=None;arm={'arm':arm_id,'binary_sha256':sha(binary),'command':command}
        try:
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Native startup failed; see '+str(out/(arm_id+'-process.txt')))
                try:
                    rpc=RPC(args.rpcport,(node/'regtest/.cookie').read_bytes().strip());info=rpc.result('getblockchaininfo');break
                except (OSError,ValueError,AssertionError,http.client.HTTPException):
                    if rpc:rpc.close();rpc=None
                    time.sleep(.05)
            else:raise RuntimeError('Native RPC startup timeout')
            assert info['chain']=='regtest';network=rpc.result('getnetworkinfo');assert not network['networkactive'] and network['connections']==0
            profile=rpc.result('getsharepoolhashstatus',None,1);assert profile['mode']=='hash-only-v7-compact-tides' and profile['activation_height']==102
            arm['native_tip']=rpc.result('getbestblockhash');arm['native_height']=info['blocks'];assert 0<=arm['native_height']+1-data['origin_height']<=3
            sequence=[]
            for request in data['requests']:
                sequence.extend([('validatesharepoolhashtemplate',[request['template_hex'],None,False]),('validatesharepoolhashshare',[request['proof_hex']])])
            controls=[rpc.call(c['method'],*c['params']) for c in data['controls']];assert all('error' in c for c in controls)
            warm=[]
            for method,params in sequence:
                response=rpc.call(method,*params);assert response.get('result',{}).get('valid') is True,response;warm.append(response)
            if reference is None:reference={'valid':warm,'controls':controls};(out/'reference-responses.json').write_bytes(canonical(reference)+b'\n')
            assert reference=={'valid':warm,'controls':controls},'Warmup validity/context differs between arms'
            samples=[];responses=[];before_cpu=cpu(process.pid);began=time.monotonic()
            for method,params in sequence:
                started=time.monotonic();response=rpc.call(method,*params);samples.append({'method':method,'seconds':time.monotonic()-started});responses.append(response)
            arm['wall_seconds']=time.monotonic()-began;arm['cpu_seconds']=cpu(process.pid)-before_cpu
            assert responses==reference['valid'];assert rpc.result('getbestblockhash')==arm['native_tip'];assert marker.read_bytes()==marker_before
            arm['response_sha256']=hashlib.sha256(canonical(responses)).hexdigest();arm['controls']=controls;arm['responses_match']=True;arm['samples']=samples
            arm['methods']={}
            for method in sorted({s['method'] for s in samples}):
                values=sorted(s['seconds'] for s in samples if s['method']==method)
                arm['methods'][method]={'count':len(values),'total_seconds':sum(values),'p50_seconds':values[math.ceil(.5*len(values))-1],'p95_seconds':values[math.ceil(.95*len(values))-1],'maximum_seconds':max(values)}
            arm['result']='passed';report['arms'].append(arm);save();print(arm_id,arm['wall_seconds'],arm['cpu_seconds'],flush=True)
        finally:
            if rpc:
                try:rpc.call('stop')
                except Exception:pass
                rpc.close()
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=30)
            log.close();assert process.poll() is not None
            archived=out/(arm_id+'-node0');assert not archived.exists();node.rename(archived);shutil.copytree(backup,node)
            assert tree(node)==original and marker.read_bytes()==marker_before
    report['original_state_restored']=tree(node)==original;report['result']='passed';report['finished_utc']=datetime.now(timezone.utc).isoformat();save()

if __name__=='__main__':main()
