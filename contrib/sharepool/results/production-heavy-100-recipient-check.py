import hashlib,io,json,sys
from pathlib import Path
repo=Path('/Users/jeronimolopez/Desktop/untitled folder/knots-sharepool')
sys.path.insert(0,str(repo/'test/functional'))
from test_framework.messages import CBlock
report_path=repo/'contrib/sharepool/results/production-gaps-heavy-100-recipients.json'
d=json.loads(report_path.read_text()); blocks=[b for e in d['epochs'] for b in e['blocks']]
assert d['result']=='passed' and len(blocks)==1
assert all(d[k]==100 for k in ('offered','acknowledged','admitted','peer_verified_admitted'))
assert all(d[k]==0 for k in ('expired','unresolved_receipts','final_backlog','current_acknowledged_backlog','peer_verification_backlog'))
e=d['epochs'][0];b=blocks[0]
assert e['initial_deferred']==0 and b['payout_recipients']==100 and b['peer_ready']
expected_scripts={b'\x00\x14'+(i+1).to_bytes(20,'big') for i in range(100)}
folder=Path('/private/tmp/sharepool-production-gaps-heavy-100-recipients/node0/regtest/blocks')
key=(folder/'xor.dat').read_bytes();assert len(key)==8
found=[]
for path in sorted(folder.glob('blk*.dat')):
 encoded=path.read_bytes()
 data=bytes(value^key[index%8] for index,value in enumerate(encoded))
 source=io.BytesIO(data);magic=data[:4]
 while source.read(4)==magic:
  length=int.from_bytes(source.read(4),'little');assert 0<length<=4_000_000
  raw=source.read(length);assert len(raw)==length
  block=CBlock();block.deserialize(io.BytesIO(raw));block.rehash()
  if block.hash==b['hash']:
   payouts={bytes(out.scriptPubKey):out.nValue for out in block.vtx[0].vout if out.nValue}
   assert len(payouts)==100 and set(payouts)==expected_scripts
   assert set(payouts.values())=={50_011_000}
   assert block.get_weight()==3_379_600 and block.vtx[0].get_weight()==12_840
   found.append({'block':block.hash,'block_bytes_sha256':hashlib.sha256(raw).hexdigest(),'payout_scripts':100,'satoshis_per_recipient':50_011_000,'native_weight':block.get_weight(),'coinbase_weight':block.vtx[0].get_weight()})
assert len(found)==1
result={'result':'passed','source':'independent read of stopped native blk file using its xor.dat key','input_report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest(),'checks':found,'no_initial_deferred':True,'one_block':True,'all_counts_and_final_backlogs_verified':True}
(repo/'contrib/sharepool/results/production-heavy-100-recipient-check.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
