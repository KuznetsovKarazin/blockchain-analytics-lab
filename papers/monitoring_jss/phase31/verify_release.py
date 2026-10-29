#!/usr/bin/env python3
"""Fail-closed offline release gate for the V7 research revision."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
REPO = PAPER.parents[1]

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def read(p):
    return json.loads(Path(p).read_text())

def run(args):
    r = subprocess.run([sys.executable, *map(str, args)], cwd=REPO, text=True, capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    print('PASS:', Path(args[0]).name, flush=True)

def regenerate_retained(script, outputs):
    """Require exact retained reports; leave the checkout unchanged on failure."""
    originals = {path: path.read_bytes() for path in outputs}
    try:
        run([script])
        changed = [str(path.relative_to(HERE)) for path, data in originals.items()
                   if not path.exists() or path.read_bytes() != data]
        assert not changed, 'Regenerated reports differ from retained outputs: ' + ', '.join(changed)
    finally:
        for path, data in originals.items():
            if not path.exists() or path.read_bytes() != data:
                path.write_bytes(data)
    return {str(path.relative_to(HERE)): digest(path) for path in outputs}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    a = parser.parse_args()
    report = {'schema': 'article2_v7_offline_release_audit_v1', 'network_requests': 0}
    with tempfile.TemporaryDirectory(prefix='article2-v7-gate-') as temp:
        temp = Path(temp)
        run([HERE/'reproduce_original.py','--out',temp/'original.json'])
        original = read(temp/'original.json')
        assert original['status']=='PASS' and original['network_requests']==0
        report['original_study_reproduction'] = original
        run([HERE/'replay_audit/run_audit.py','--out',temp/'seven'])
        seven = read(temp/'seven/REPLAY_AUDIT.json')
        assert seven['status']=='PASS' and seven['independent_policy_cells_matched']==441
        assert seven['frozen_files_unchanged'] and seven['total_selected_transactions']==525
        report['seven_stream_reproduction'] = seven
        report['seven_stream_input_sha256'] = read(temp/'seven/INPUT_SHA256.json')
        # Regenerate each extension once, require its retained outputs exactly,
        # and embed the resulting evidence in the single portable release report.
        cohort = HERE/'cohort_audit'
        deployment = cohort/'deployment'
        three = HERE/'three_cases'
        outputs = {}
        for script, names in [
                (cohort/'recompute_census.py', ['CENSUS_DENOMINATORS.json', 'CENSUS_DENOMINATORS.csv']),
                (cohort/'audit_catalogue.py', ['CATALOGUE_DISPOSITION.json', 'CATALOGUE_DISPOSITION.csv']),
                (deployment/'audit_deployments.py', ['DEPLOYMENT_AUDIT.json', 'DEPLOYMENT_CASES.csv']),
                (three/'observe_three_cases.py', ['event_observations.json', 'role_observations.json', 'summary.json'])]:
            outputs.update(regenerate_retained(script, [script.parent/name for name in names]))
        census = read(cohort/'CENSUS_DENOMINATORS.json')
        assert [census['summary'][k] for k in ['emitter_days','selected_transactions','zero_transaction_days','nonempty_days','nonempty_days_below20']] == [480,44780,302,178,108]
        catalogue = read(cohort/'CATALOGUE_DISPOSITION.json')
        assert catalogue['counts']['source_files']==67 and catalogue['counts']['ethereum_mainnet_files']==28
        creation = read(deployment/'DEPLOYMENT_AUDIT.json')
        assert creation['complete'] and creation['accepted']==creation['total']==16
        observations = read(three/'summary.json')
        assert observations['greedy_B5_cells_reproduced']==12
        assert sum(x['selected_transactions'] for x in observations['cases'])==125
        assert all(x['status']=='PASS' for x in observations['checks'])
        run([three/'saddle_rank_decomposition.py', '--check'])
        saddle = read(three/'saddle_rank_decomposition.json')
        assert saddle['status']=='PASS' and (saddle['rank_numerator'],saddle['rank_denominator'])==(3,21)
        outputs['three_cases/saddle_rank_decomposition.json'] = digest(three/'saddle_rank_decomposition.json')
        report['census'] = census['summary']
        report['extension_study_reproduction'] = {
            'census_denominator_audit': census,
            'catalogue_reconciliation': catalogue,
            'deployment_sensitivity': creation,
            'three_case_observation_audit': observations,
            'saddle_rank_decomposition': saddle,
            'retained_outputs_sha256': outputs,
            'retained_output_comparison': 'Exact bytes for nine regenerated JSON/CSV outputs; read-only exact decomposition check.'}
        raw = HERE/'raw_payload_audit'
        run([raw/'verify_all.py','--archive',raw/'raw_observations.zip','--integrity-tests','--out',temp/'raw.json'])
        r = read(temp/'raw.json')
        assert r['status']=='PASS' and r['verified_transactions']==125 and r['all_emitter_logs']==2103
        assert r['archive_extracted_to_fresh_temporary_directory']
        assert len(r['negative_integrity_tests'])==3 and all(x['rejected'] for x in r['negative_integrity_tests'])
        report['phase30_raw_observations'] = r
        # A full Nomad source cohort is mandatory for this release, not inferred
        # from a partial checkpoint or a successful command on a subset.
        nomad = HERE/'nomad'
        accepted = read(nomad/'ACCEPTED_DATA.json')
        rel = Path(accepted['relative_path'])
        assert not rel.is_absolute() and '..' not in rel.parts
        data = nomad/rel
        assert data.resolve().is_relative_to(nomad.resolve())
        assert accepted['status']=='COMPLETE' and accepted['selected_transactions']==930
        assert digest(data/'acquisition_manifest.json')==accepted['manifest_sha256']
        source = read(data/'acquisition_manifest.json')
        assert source['status']=='COMPLETE' and source['selected_transactions']==930
        run([HERE/'nomad_independent/verify_nomad.py','--data',data,'--results',nomad/'results','--out',temp/'nomad.json'])
        independent = read(temp/'nomad.json')
        assert independent['status']=='PASS'
        run([nomad/'replay_and_verify.py','--data',data,'--out',temp/'nomad_rebuilt'])
        expected = read(nomad/'results/label_blind_replay.json')
        got = read(temp/'nomad_rebuilt/label_blind_replay.json')
        assert got==expected, 'Nomad complete label-blind replay changed'
        assert len(got['case_score_rows'])==63 and all(x['selected_tx']==930 for x in got['case_score_rows'])
        report['nomad'] = {'accepted_source':accepted,'independent_audit':independent,
                           'replay_cells':63,'replay_sha256':digest(nomad/'results/label_blind_replay.json')}
    article = PAPER/'jss_latex_v7_review'
    tex = (article/'main.tex').read_text()
    bib = (article/'references.bib').read_text()
    keys = set(re.findall(r'@\w+\s*\{\s*([^,]+)',bib))
    cited = {k.strip() for group in re.findall(r'\\cite\w*\{([^}]+)\}',tex) for k in group.split(',')}
    assert cited <= keys, sorted(cited-keys)
    assert 'When Can a Blockchain Monitor Make a Decision?' in tex
    assert 'once published' not in tex
    report['manuscript'] = {'source_sha256':digest(article/'main.tex'),'bibliography_sha256':digest(article/'references.bib'),
                            'citation_keys':len(cited),'undefined_citations':sorted(cited-keys)}
    report['limits'] = ['Source identity and payload agreement is not receipt-root authentication.',
                        'Seven low-volume streams and the additional Nomad stream are exploratory selections.',
                        'Known reference inventories remain incomplete; no population recall or false-positive rate is established.',
                        'Full Phase30 raw indexed responses are retained; other phases retain the explicitly documented source tiers.']
    report['status'] = 'PASS'
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS: original studies, 441 seven-stream cells, census/catalogue/deployment/three-case reports, 125 retained raw observations, 930 complete Nomad transactions, 63 independent Nomad cells, manuscript checks')

if __name__=='__main__':
    main()
