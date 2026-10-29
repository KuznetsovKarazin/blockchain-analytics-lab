#!/usr/bin/env python3
"""Package the compiled manuscript, verified sources and review audit."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

HERE=Path(__file__).resolve().parent
ARTICLE=HERE.parent/'jss_latex_v7_review'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source-commit',required=True)
    p.add_argument('--audit',type=Path,required=True)
    a=p.parse_args()
    audit=json.loads(a.audit.read_text());assert audit['status']=='PASS'
    assert audit['manuscript']['source_sha256']==sha(ARTICLE/'main.tex')
    info=subprocess.check_output(['pdfinfo',str(ARTICLE/'main.pdf')],text=True)
    pages=int(next(x.split(':',1)[1] for x in info.splitlines() if x.startswith('Pages:')))
    assert 1<=pages<=34, pages
    (ARTICLE/'PDF_SHA256.txt').write_text(sha(ARTICLE/'main.pdf')+'  main.pdf\n')
    shutil.copy2(a.audit,ARTICLE/'REPRODUCTION_REPORT.json')
    shutil.copy2(HERE/'REVIEW_RESPONSE_RU.md',ARTICLE/'REVIEW_RESPONSE_RU.md')
    names=['main.tex','references.bib','alerts_table.tex','source_census_tables.tex',
           'fig1_attack_time_selected.pdf','fig2_history_eligibility_six_views.pdf',
           'fig3_incident_relative_alerts.pdf','fig4_external_readiness_census.pdf',
           'README.md','HIGHLIGHTS.md','main.pdf','PDF_SHA256.txt','REPRODUCTION_REPORT.json','REVIEW_RESPONSE_RU.md']
    manifest={'edition':'Article2 JSS V7 research review revision',
              'baseline_commit':'651daa926bb3803ad76227389a4fb35c1027da63',
              'source_commit':a.source_commit,'release_tag':'article2-jss-v7-2026-10-29',
              'official_elsarticle_commit':'04aee43a9049051128c5d58b617dcd05e34df8b4',
              'pdf_pages':pages,'offline_audit_status':audit['status'],
              'journal_submission_performed':False,'zenodo_doi':None,
              'files_sha256':{n:sha(ARTICLE/n) for n in names}}
    (ARTICLE/'RELEASE_MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    names.append('RELEASE_MANIFEST.json')
    with zipfile.ZipFile(ARTICLE/'Article2_JSS_V7_LaTeX_PDF.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for n in names:
            item=zipfile.ZipInfo(n,(2026,10,29,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED;item.external_attr=0o100644<<16
            z.writestr(item,(ARTICLE/n).read_bytes())
    print(json.dumps({'pages':pages,'zip_sha256':sha(ARTICLE/'Article2_JSS_V7_LaTeX_PDF.zip'),'pdf_sha256':sha(ARTICLE/'main.pdf')}))

if __name__=='__main__':main()
