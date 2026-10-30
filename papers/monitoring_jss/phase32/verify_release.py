#!/usr/bin/env python3
"""Fail-closed offline V8 audit, deterministic packaging and package verification.

The scientific gate uses retained observations and source receipts, not a network
service. It does not claim original-Parquet re-extraction or receipt-root proof.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
REPO = PAPER.parents[1]
ARTICLE = PAPER / 'jss_latex_v8_final'
TAG = 'article2-jss-v8-2026-10-30'
CLASS_COMMIT = '04aee43a9049051128c5d58b617dcd05e34df8b4'
BASELINES = {
    'article2-jss-v7-2026-10-29': 'aab963c5c5aa60adb7af5f04bc86601f92c67b87',
    'article2-jss-v6.1-2026-10-29': '651daa926bb3803ad76227389a4fb35c1027da63',
}
FIGURES = ('fig1_attack_time_selected.pdf', 'fig2_incident_relative_alerts.pdf',
           'fig3_external_readiness_census.pdf')
SOURCE_FILES = ('main.tex', 'references.bib', 'alerts_table.tex',
                'source_census_tables.tex', *FIGURES, 'README.md', 'HIGHLIGHTS.md',
                'Highlights.docx', 'Declaration_of_Interest.docx', 'REVIEW_RESPONSE_RU.md')
PACKAGE_FILES = (*SOURCE_FILES, 'main.pdf', 'PDF_SHA256.txt', 'REPRODUCTION_REPORT.json')
ZIP_NAME = 'Article2_JSS_V8_LaTeX_PDF.zip'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(script, *args):
    result = subprocess.run([sys.executable, str(script), *map(str, args)],
                            cwd=REPO, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print('PASS:', Path(script).relative_to(PAPER), flush=True)


def text_normalized(value):
    return ' '.join(value.replace('~', ' ').replace('\u00a0', ' ').split())


def docx_paragraphs(path):
    with zipfile.ZipFile(path) as archive:
        need(archive.testzip() is None, 'Corrupt DOCX: ' + str(path))
        xml = ET.fromstring(archive.read('word/document.xml'))
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    return [text_normalized(''.join(p.itertext())) for p in xml.findall('.//w:p', ns)]


def manuscript_checks(census):
    for name in SOURCE_FILES:
        need((ARTICLE / name).is_file(), 'Missing manuscript input: ' + name)
    tex = (ARTICLE / 'main.tex').read_text()
    combined = tex + '\n' + '\n'.join((ARTICLE / n).read_text() for n in
                                      ('alerts_table.tex', 'source_census_tables.tex'))
    bib = (ARTICLE / 'references.bib').read_text()
    keys = set(re.findall(r'@\w+\s*\{\s*([^,]+)', bib))
    citations = {k.strip() for group in re.findall(r'\\cite\w*\{([^}]+)\}', combined)
                 for k in group.split(',')}
    need(citations <= keys, 'Undefined citations: ' + ', '.join(sorted(citations - keys)))
    labels = re.findall(r'\\label\{([^}]+)\}', combined)
    refs = set(re.findall(r'\\(?:ref|eqref|autoref)\{([^}]+)\}', combined))
    need(len(labels) == len(set(labels)), 'Duplicate manuscript labels')
    need(refs <= set(labels), 'Undefined labels: ' + ', '.join(sorted(refs - set(labels))))
    figures = re.findall(r'\\includegraphics(?:\[[^]]*\])?\{([^}]+)\}', combined)
    need(set(figures) == set(FIGURES) and len(figures) == 3, 'Exactly three cited figures required')
    need({p.name for p in ARTICLE.glob('fig*.pdf')} == set(FIGURES), 'Unused figure asset present')
    need('When Can a Blockchain Monitor Make a Decision?' in tex, 'Title changed')
    need('\\journal{Journal of Systems and Software}' in tex, 'Journal metadata missing')
    need('\\documentclass[preprint,12pt,authoryear]{elsarticle}' in tex, 'Unreviewed typesetting format')
    need('\\author[aff1,aff2,aff3]{Oleksandr Kuznetsov' in tex, 'Author/affiliations missing')
    need(len(re.findall(r'\\address\[aff[123]\]', tex)) == 3, 'Three affiliation records required')
    for value in ('SMARTEST Research Center', 'Via Isimbardi 10', 'Novedrate (CO)',
                  '22060', 'eCampus University', 'Karazin Kharkiv National University',
                  '0000-0003-2331-6326', 'oleksandr.kuznetsov@uniecampus.it'):
        need(value in tex, 'Author field missing: ' + value)
    kw = re.search(r'\\begin\{keyword\}(.*?)\\end\{keyword\}', tex, re.S)
    need(kw is not None and len([x for x in kw.group(1).split('\\sep') if x.strip()]) == 6,
         'Expected six populated keywords')
    abstract = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', tex, re.S)
    need(abstract is not None, 'Abstract absent')
    primary = census['extended22_unique_emitter_days']
    # Bind the headline to deduplicated nonempty days, not the old sixteen-emitter cohort.
    for n in (primary['nonempty_days'], primary['nonempty_below20_days']):
        need(re.search(r'(?<!\d)' + str(n) + r'(?!\d)', abstract.group(1)),
             'Abstract does not use current nonempty-day census')
    need('unit burst capacity' in abstract.group(1), 'Abstract omits bucket capacity')
    need("attack-day burst" in abstract.group(1), 'Abstract omits Nomad burst qualification')
    sections = ('Competing interests', 'Funding',
                'Declaration of generative AI and AI-assisted technologies in the manuscript preparation process')
    declaration_text = {}
    for title in sections:
        found = re.search(r'\\section\*\{' + re.escape(title) + r'\}\s*(.*?)(?=\\section\*|\\appendix)', tex, re.S)
        need(found is not None and len(found.group(1).strip()) > 30, 'Empty declaration: ' + title)
        declaration_text[title] = text_normalized(found.group(1))
    need('PETs4DeFi' in declaration_text['Funding'] and '101308999' in declaration_text['Funding'],
         'Grant acknowledgement absent')
    need('European Cybersecurity Competence Centre' in declaration_text['Funding']
         and 'Neither the European Union' in declaration_text['Funding'], 'EU/ECCC disclosure incomplete')
    need('reports financial support' in declaration_text['Competing interests'], 'Known financial support not disclosed')
    need('OpenAI ChatGPT and Codex' in declaration_text[sections[-1]], 'Writing tools not disclosed')
    need('ChatGPT and Codex assisted development' in tex and 'no language-model inference' in tex,
         'Research-code assistance not disclosed in Methods')
    need('no competing' not in declaration_text['Competing interests'].lower(),
         'Unconfirmed negative COI assertion introduced')
    need(not re.search(r'\b(?:TODO|TBD|FIXME|PLACEHOLDER)\b|\[INSERT|to be completed|pending confirmation',
                       combined, re.I), 'Unfilled manuscript placeholder')
    need('once published' not in (tex + (ARTICLE / 'README.md').read_text()).lower(),
         'Obsolete publication wording')
    need(TAG in tex and BASELINES['article2-jss-v7-2026-10-29'] in tex
         and BASELINES['article2-jss-v6.1-2026-10-29'] in tex, 'Release provenance absent')
    highlights = [x[2:].strip() for x in (ARTICLE / 'HIGHLIGHTS.md').read_text().splitlines()
                  if x.startswith('- ')]
    need(len(highlights) == 5 and all(0 < len(x) <= 85 for x in highlights), 'Highlights count/length')
    need('unit burst capacity' in highlights[4] and 'attack-day burst' in highlights[3],
         'Highlight qualifications absent')
    need(str(primary['nonempty_days']) in highlights[1]
         and str(primary['nonempty_below20_days']) in highlights[1], 'Stale census highlight')
    paragraphs = docx_paragraphs(ARTICLE / 'Highlights.docx')
    need(all(text_normalized(h) in paragraphs for h in highlights), 'DOCX Highlights disagree with Markdown')
    coi = docx_paragraphs(ARTICLE / 'Declaration_of_Interest.docx')
    need(declaration_text['Competing interests'] in coi, 'DOCX COI disagrees with manuscript')
    return {'files_sha256': {n: sha(ARTICLE / n) for n in SOURCE_FILES},
            'source_sha256': sha(ARTICLE / 'main.tex'), 'citation_keys': len(citations),
            'undefined_citations': [], 'undefined_labels': [], 'figures': list(FIGURES),
            'keyword_count': 6, 'highlight_characters': list(map(len, highlights)),
            'declarations_populated': list(sections), 'editable_documents_match_manuscript': True,
            'layout_verification': 'Separate visual inspection required; this gate checks content and package integrity.'}



def figure_census_checks():
    census_dir = HERE / 'census_completion'
    plot = read(census_dir / 'audit/census_22_emitters.json')
    need(plot['schema'] == 'phase32_census_plot_binding_v1', 'Unbound census plot')
    for name, expected in plot['inputs_sha256'].items():
        path = (PAPER if name.startswith('phase28/') else census_dir) / name
        need(sha(path) == expected, 'Figure input changed: ' + name)
    need(plot['output_pdf_sha256'] == sha(ARTICLE / FIGURES[2]), 'Figure output checksum changed')
    with (census_dir / 'audit/COMBINED_UNIQUE_EMITTER_DAILY.csv').open() as handle:
        days = list(csv.DictReader(handle))
    groups = defaultdict(list)
    for day in days:
        groups[day['core_address']].append(int(day['tx']))
    cores = [r['core_address'] for r in plot['rows']]
    need(len(cores) == len(set(cores)) == 22 and set(cores) == set(groups),
         'Figure must contain every unique emitter exactly once')
    order = []
    for case in (read(PAPER / 'phase28/CANDIDATE_FRAME.json')['cases']
                 + read(census_dir / 'CANDIDATE_FRAME.json')['cases']):
        if case['core_address'] not in order:
            order.append(case['core_address'])
    need(cores == order and plot['original16_then_new6_divider'], 'Figure cohort order changed')
    for row in plot['rows']:
        values = groups[row['core_address']]
        expected = {'unique_days': len(values), 'below20_days': sum(n < 20 for n in values),
                    'nonempty_below20_days': sum(0 < n < 20 for n in values),
                    'nonempty_days': sum(n > 0 for n in values),
                    'selected_transaction_observations': sum(values)}
        need(all(row[k] == v for k, v in expected.items()), 'Figure counts disagree: ' + row['label'])
    need((plot['all_unique_emitter_days'], plot['all_nonempty_days'],
          plot['all_nonempty_below20_days']) == (663, 277, 130), 'Figure total changed')
    figure = ARTICLE / FIGURES[2]
    need(figure.read_bytes() == (census_dir / 'audit/census_22_emitters.pdf').read_bytes(),
         'Manuscript figure is not the retained census figure')
    return {'status': 'PASS', 'emitter_rows_independently_recounted': 22,
            'unique_days': len(days), 'figure_sha256': sha(figure),
            'plot_data_sha256': sha(census_dir / 'audit/census_22_emitters.json'),
            'plot_script_sha256': sha(census_dir / 'plot_census.py'),
            'scope': 'Independent numeric reconstruction and exact figure-copy binding; graphical rendering inspected separately.'}


def audit(out):
    report = {'schema': 'article2_v8_offline_release_audit_v1', 'network_requests': 0,
              'baseline_releases': BASELINES, 'gate_sha256': sha(__file__)}
    with tempfile.TemporaryDirectory(prefix='article2-v8-gate-') as temp_name:
        temp = Path(temp_name)
        run(PAPER / 'phase31/verify_release.py', '--out', temp / 'v7.json')
        baseline = read(temp / 'v7.json')
        need(baseline['status'] == 'PASS', 'V7 scientific baseline failed')
        report['v7_baseline_reproduction'] = baseline
        census_dir = HERE / 'census_completion'
        run(census_dir / 'verify_census.py', '--out', temp / 'census')
        census = read(temp / 'census/CENSUS_AUDIT.json')
        need(census['status'] == 'PASS' and census['network_requests'] == 0, 'Census verification failed')
        for name in ('CENSUS_AUDIT.json', 'NEW_CASES.csv', 'COMBINED_WINDOW_DAILY.csv',
                     'COMBINED_UNIQUE_EMITTER_DAILY.csv'):
            need((temp / 'census' / name).read_bytes() == (census_dir / 'audit' / name).read_bytes(),
                 'Retained census report changed: ' + name)
        primary = census['extended22_unique_emitter_days']
        need([primary[k] for k in ('emitter_days', 'zero_days', 'nonempty_days',
                                  'nonempty_below20_days', 'ge20_days',
                                  'selected_transaction_observations', 'core_emitted_events')]
             == [663, 386, 277, 130, 147, 51452, 100511], 'Completed census changed')
        need(census['extended23_window_weighted']['emitter_days'] == 690
             and len(census['duplicate_circle_days']) == 27, 'Window deduplication changed')
        deploy = census['deployment_sensitivity']
        need((deploy['including_partial_creation_dates']['emitter_days'],
              deploy['including_partial_creation_dates']['below20_days'],
              deploy['fully_after_creation_date']['emitter_days'],
              deploy['fully_after_creation_date']['below20_days']) == (449, 302, 439, 293),
             'Deployment sensitivity changed')
        report['completed_census'] = census
        report['census_figure'] = figure_census_checks()
        run(census_dir / 'test_integrity.py', '--out', temp / 'census_integrity.json')
        need((temp / 'census_integrity.json').read_bytes() == (census_dir / 'audit/INTEGRITY_TESTS.json').read_bytes(),
             'Census integrity-test report changed')
        integrity = read(temp / 'census_integrity.json')
        need(integrity['status'] == 'PASS' and len(integrity['checks']) == 3
             and all(x['status'] == 'PASS_REJECTED' for x in integrity['checks']), 'Census altered-data checks failed')
        report['census_integrity_tests'] = integrity
        join_dir = HERE / 'nomad_join'
        run(join_dir / 'verify_join.py', '--check')
        run(join_dir / 'independent_check.py', '--check')
        join = read(join_dir / 'JOIN_REPORT.json')
        independent = read(join_dir / 'INDEPENDENT_CHECK.json')
        need(join['status'] == independent['status'] == 'PASS', 'Nomad documentary join failed')
        need(join['network_requests_during_verification'] == independent['network_requests'] == 0,
             'Network-dependent join')
        need([join['count_funnel'][k] for k in ('grouped_candidates', 'protocol_listed_grouped_candidates',
                                              'greedy_B5_notifications', 'greedy_B5_hard_cap_rejections')]
             == [12, 12, 5, 7], 'Nomad dispatch result changed')
        need(join['reference_reconciliation']['selected_reference_hashes'] == 877
             and join['timing']['seconds_first_reference_to_budget_exhaustion'] == 6302,
             'Nomad join population or timing changed')
        report['nomad_documentary_join'] = join
        report['nomad_separate_implementation'] = independent
        bucket_dir = HERE / 'saddle_bucket'
        run(bucket_dir / 'audit.py', '--out', temp / 'saddle_bucket.json')
        need((temp / 'saddle_bucket.json').read_bytes() == (bucket_dir / 'AUDIT.json').read_bytes(),
             'Saddle/bucket retained audit changed')
        bucket = read(temp / 'saddle_bucket.json')
        need(bucket['status'] == 'PASS' and bucket['network_requests'] == 0, 'Saddle/bucket audit failed')
        need(bucket['saddle']['observations'][0]['rank_exact'] == '1/17'
             and not bucket['saddle']['observations'][0]['descriptive_rank_le_1_20'],
             'Initial Saddle rank interpretation changed')
        variants = {x['variant']: x for x in bucket['schnoodle']['variants'] if x['budget'] == 5}
        need([variants[k]['notifications'] for k in ('original_unit_capacity', 'capacity_B_initial_one',
                                                     'capacity_B_initial_B')] == [21, 24, 27],
             'Bucket-capacity sensitivity changed')
        report['saddle_and_bucket_sensitivity'] = bucket
        report['manuscript'] = manuscript_checks(census)
    report['limits'] = [
        'The completed frame covers every Ethereum-mainnet PoC file in the pinned March–September 2022 catalogue, not all Ethereum incidents.',
        'Census recounting starts at retained selected coordinates; original Parquet byte-to-selection re-extraction requires network acquisition.',
        'Nomad list membership is documentary evidence, not complete incident roles, precision or population recall.',
        'The post-review bucket-capacity sensitivity is distinct from the original fixed-policy experiment.',
        'Source identity and payload agreement are not receipt-root authentication.',
        'Declarations disclose verified support and AI assistance; no absence of undisclosed interests is inferred.',
    ]
    report['status'] = 'PASS'
    save(out, report)
    print('PASS: V7 baseline, complete 22-emitter census, independent Nomad join, Saddle/capacity sensitivity and V8 manuscript')


def package(source_commit, audit_path):
    need(re.fullmatch('[0-9a-f]{40}', source_commit), 'Full source commit required')
    for name in SOURCE_FILES:
        revision_path = source_commit + ':' + str((ARTICLE / name).relative_to(REPO))
        committed = subprocess.check_output(['git', 'show', revision_path], cwd=REPO)
        need(committed == (ARTICLE / name).read_bytes(), 'Source commit bytes disagree: ' + name)
    source_epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', source_commit], cwd=REPO, text=True).strip())
    need(os.environ.get('SOURCE_DATE_EPOCH') == str(source_epoch), 'Build epoch does not match source commit')
    need(os.environ.get('FORCE_SOURCE_DATE') == '1', 'FORCE_SOURCE_DATE=1 required for release packaging')
    audit_report = read(audit_path)
    need(audit_report['status'] == 'PASS'
         and audit_report['schema'] == 'article2_v8_offline_release_audit_v1', 'Valid V8 audit required')
    need(audit_report['gate_sha256'] == sha(__file__), 'Audit from different gate source')
    need(audit_report['manuscript']['files_sha256'] == {n: sha(ARTICLE / n) for n in SOURCE_FILES},
         'Manuscript input changed after audit')
    info = subprocess.check_output(['pdfinfo', str(ARTICLE / 'main.pdf')], text=True)
    pages = int(next(x.split(':', 1)[1] for x in info.splitlines() if x.startswith('Pages:')))
    need(1 <= pages <= 34, 'Unexpected page count: ' + str(pages))
    pdf_text = subprocess.check_output(['pdftotext', str(ARTICLE / 'main.pdf'), '-'], text=True)
    need('PETs4DeFi' in pdf_text and 'SMARTEST' in pdf_text and '101308999' in pdf_text,
         'Compiled PDF lacks metadata/declarations')
    need('??' not in pdf_text, 'Unresolved PDF reference')
    (ARTICLE / 'PDF_SHA256.txt').write_text(sha(ARTICLE / 'main.pdf') + '  main.pdf\n')
    shutil.copyfile(audit_path, ARTICLE / 'REPRODUCTION_REPORT.json')
    manifest = {
        'edition': 'Article2 JSS V8 final review revision', 'source_commit': source_commit,
        'release_tag': TAG, 'baseline_releases': BASELINES,
        'official_elsarticle_commit': CLASS_COMMIT, 'pdf_pages': pages,
        'build_environment': {
            'source_date_epoch': source_epoch, 'force_source_date': True,
            'tex_engine': subprocess.check_output(['pdflatex', '--version'], text=True).splitlines()[0],
            'bibliography_engine': subprocess.check_output(['bibtex', '--version'], text=True).splitlines()[0],
            'python': sys.version.split()[0],
        },
        'offline_audit_status': 'PASS', 'journal_submission_performed': False, 'zenodo_doi': None,
        'files_sha256': {n: sha(ARTICLE / n) for n in PACKAGE_FILES},
        'source_boundary': 'The submission ZIP contains article inputs and verification reports. Full datasets and scripts are retained in the tagged repository.',
    }
    save(ARTICLE / 'RELEASE_MANIFEST.json', manifest)
    with zipfile.ZipFile(ARTICLE / ZIP_NAME, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in (*PACKAGE_FILES, 'RELEASE_MANIFEST.json'):
            entry = zipfile.ZipInfo(name, (2026, 10, 30, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, (ARTICLE / name).read_bytes())
    verify_package(source_commit)


def verify_package(source_commit=None):
    manifest = read(ARTICLE / 'RELEASE_MANIFEST.json')
    need(manifest['release_tag'] == TAG and manifest['baseline_releases'] == BASELINES,
         'Release identity changed')
    need(manifest['official_elsarticle_commit'] == CLASS_COMMIT, 'Class pin changed')
    info = subprocess.check_output(['pdfinfo', str(ARTICLE / 'main.pdf')], text=True)
    pages = int(next(x.split(':', 1)[1] for x in info.splitlines() if x.startswith('Pages:')))
    need(manifest['pdf_pages'] == pages and 1 <= pages <= 34, 'PDF page count disagrees')
    need(re.fullmatch('[0-9a-f]{40}', manifest['source_commit']), 'Invalid source commit')
    if source_commit is not None:
        need(manifest['source_commit'] == source_commit, 'Unexpected source commit')
    need(manifest['files_sha256'] == {n: sha(ARTICLE / n) for n in PACKAGE_FILES},
         'Packaged file hashes disagree')
    need((ARTICLE / 'PDF_SHA256.txt').read_text() == sha(ARTICLE / 'main.pdf') + '  main.pdf\n',
         'PDF hash record disagrees')
    report = read(ARTICLE / 'REPRODUCTION_REPORT.json')
    need(report['status'] == 'PASS' and report['manuscript']['files_sha256']
         == {n: sha(ARTICLE / n) for n in SOURCE_FILES}, 'Reproduction report not bound to package inputs')
    with zipfile.ZipFile(ARTICLE / ZIP_NAME) as archive:
        need(archive.testzip() is None, 'Invalid ZIP')
        need(sorted(archive.namelist()) == sorted((*PACKAGE_FILES, 'RELEASE_MANIFEST.json')),
             'Unexpected, duplicate or missing ZIP member')
        for name in archive.namelist():
            need(archive.read(name) == (ARTICLE / name).read_bytes(), 'ZIP bytes disagree: ' + name)
    print(json.dumps({'status': 'PASS', 'pdf_pages': manifest['pdf_pages'],
                      'pdf_sha256': sha(ARTICLE / 'main.pdf'), 'zip_sha256': sha(ARTICLE / ZIP_NAME),
                      'source_commit': manifest['source_commit']}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path, help='Run the complete offline scientific and manuscript audit')
    mode.add_argument('--package', action='store_true', help='Package an already compiled, audited article')
    mode.add_argument('--verify-package', action='store_true', help='Check all distributed package bytes')
    parser.add_argument('--source-commit')
    parser.add_argument('--audit', type=Path)
    args = parser.parse_args()
    if args.out:
        audit(args.out)
    elif args.package:
        need(args.source_commit and args.audit, '--package requires --source-commit and --audit')
        package(args.source_commit, args.audit)
    else:
        verify_package(args.source_commit)


if __name__ == '__main__':
    main()
