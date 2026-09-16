#!/usr/bin/env python3
"""Build a temporary retention-off control, then restore exact source and build."""
from pathlib import Path
import hashlib,json,shutil,subprocess,time
ROOT=Path('/Users/jeronimolopez/Desktop/untitled folder/knots-sharepool')
OUT=Path('/private/tmp/sharepool-native-retention-ab')
BUILD=Path('/private/tmp/sharepool-native-build')
CMAKE='/private/tmp/sharepool-build-tools-20260912/cmake/data/bin/cmake'
source=ROOT/'src/validation.cpp';original=source.read_bytes();baseline=OUT/'validation.cpp.retention-on'
assert original==baseline.read_bytes()
changed=original.decode()
for function in ['ValidateSharePoolHashHistoricalTemplateUnlocked','ValidateSharePoolHashProofUnlocked']:
 start=changed.index('sharepool::hashonly::Result '+function)
 position=changed.index('sharepool::DecodedSnapshotCache snapshots{hashonly::MAX_DEPENDENCY_BYTES};',start)
 old='sharepool::DecodedSnapshotCache snapshots{hashonly::MAX_DEPENDENCY_BYTES};'
 changed=changed[:position]+changed[position:].replace(old,'sharepool::DecodedSnapshotCache snapshots{hashonly::MAX_DEPENDENCY_BYTES, 0};',1)
assert changed.count('sharepool::DecodedSnapshotCache snapshots{hashonly::MAX_DEPENDENCY_BYTES, 0};')==2
assert changed.count('sharepool::DecodedSnapshotCache snapshots{hashonly::MAX_DEPENDENCY_BYTES};')==1
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
report={'temporary_source_change':'Disable only historical-template and share-proof optional decoded retention; keep preparation-job cache and all validation rules.','source_on_sha256':sha(source),'binary_on_sha256':sha(OUT/'bitcoind-retention-on')}
command=[CMAKE,'--build',str(BUILD),'--parallel','2','--target','bitcoind']
try:
 source.write_text(changed);(OUT/'validation.cpp.retention-off').write_text(changed)
 report['source_off_sha256']=sha(source)
 with (OUT/'build-off.txt').open('w') as log: result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
 report['off_build_exit_code']=result.returncode
 result.check_returncode()
 shutil.copy2(BUILD/'bin/bitcoind',OUT/'bitcoind-retention-off');report['binary_off_sha256']=sha(OUT/'bitcoind-retention-off')
finally:
 source.write_bytes(original)
 with (OUT/'build-restore.txt').open('w') as log: restored=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
 report['restore_build_exit_code']=restored.returncode
 report['source_restored']=source.read_bytes()==original
 report['rebuilt_on_sha256']=sha(BUILD/'bin/bitcoind')
 report['restored_binary_matches_original']=report['rebuilt_on_sha256']==report['binary_on_sha256']
 (OUT/'build-variants.json').write_text(json.dumps(report,indent=2)+'\n')
 restored.check_returncode()
 assert report['restored_binary_matches_original'],report
print(json.dumps(report,indent=2))
