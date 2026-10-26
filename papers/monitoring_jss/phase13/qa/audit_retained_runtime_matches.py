#!/usr/bin/env python3
"""Independent complete-byte comparison of retained runtime observations."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[4]
WORK = ROOT.parent
PHASE = ROOT / 'papers/monitoring_jss/phase13'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    compiler_path = WORK / 'phase11_lifi_private/compilation_attempt1/cbridge_facet/compiler_output.json'
    assert sha(compiler_path) == '2aa02601b74f98184ac79af132271dca6c328a4e53ded616e605d0ad7a5a1919'
    compilation_path = ROOT / 'papers/monitoring_jss/phase11/compilation/compilation_results.json'
    assert sha(compilation_path) == '7c59ce06ac9c3034c86e8caba5e0c881a9605e328ab52b7c9f92b0124b263b64'
    assert read(compilation_path)['all_exact'] is True
    table_path = PHASE / 'acquisition/runtime_match_table.json'
    table = read(table_path)
    source = read(compiler_path)
    attempt = WORK / 'phase13_lifi_private/code_window_attempt1'
    summary, plan, ledger = (read(attempt / n) for n in ('summary.json', 'frozen_plan.json', 'requests.json'))
    audit = read(PHASE / 'qa/independent_actual_review.json')
    assert audit['status'] == 'PASS_INDEPENDENT_CODE_AND_WINDOW_EVENT_AUDIT'
    assert audit['summary_sha256'] == sha(attempt / 'summary.json')
    inputs = table['input_bindings']
    assert inputs['compiled_output_sha256'] == sha(compiler_path)
    assert inputs['phase11_compilation_result_sha256'] == sha(compilation_path)
    assert inputs['capture_summary_sha256'] == sha(attempt / 'summary.json')
    assert inputs['capture_plan_sha256'] == sha(attempt / 'frozen_plan.json')
    assert inputs['capture_requests_sha256'] == sha(attempt / 'requests.json')
    assert inputs['comparison_program_sha256'] == sha(PHASE / 'acquisition/compare_retained_runtimes.py')
    inventory = {(row['source_path'], row['contract_name']): row for row in table['candidate_inventory']}
    contracts = {(path, name): value for path, contracts in source['contracts'].items() for name, value in contracts.items()}
    assert inventory.keys() == contracts.keys() and len(inventory) == len(table['candidate_inventory']) == 59
    eligible, excluded = {}, 0
    for key, contract in sorted(contracts.items()):
        deployed = contract['evm']['deployedBytecode']
        raw_hex = deployed['object']
        row = inventory[key]
        assert row['link_reference_file_count'] == len(deployed.get('linkReferences', {}))
        assert row['immutable_reference_count'] == len(deployed.get('immutableReferences', {}))
        if raw_hex == '':
            assert row['status'] == 'EMPTY_RUNTIME_NOT_A_COMPARISON_CANDIDATE' and row['runtime_bytes'] == 0
            excluded += 1
        else:
            assert isinstance(raw_hex, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2})+', raw_hex)
            raw = bytes.fromhex(raw_hex)
            assert row['status'] == 'NONEMPTY_FULL_BYTES_COMPARISON_CANDIDATE'
            assert row['runtime_bytes'] == len(raw) and row['runtime_sha256'] == hashlib.sha256(raw).hexdigest()
            eligible[key[0] + ':' + key[1]] = raw
        assert row['full_runtime_includes_compiler_metadata'] is True
    assert len(eligible) == 36 and excluded == 23
    assert table['compiled_source_path_count'] == len(source['contracts']) == 44
    assert table['nonempty_full_bytes_candidate_count'] == len(eligible)
    assert table['excluded_empty_count'] == excluded and table['excluded_missing_or_nonhex_count'] == 0
    assert table['compiled_contract_count'] == 59 and table['comparison_pair_count'] == 19 * 36 == 684
    observations = table['observations']
    assert len(observations) == len(summary['runtime_observations']) == table['observation_count'] == 19
    matches = []
    for capture, proposed in zip(summary['runtime_observations'], observations):
        for key in ('checkpoint', 'block_number', 'block_hash', 'address', 'runtime_bytes', 'runtime_sha256', 'runtime_keccak256'):
            assert proposed[key] == capture[key]
        planned = next(row for row in plan['code_observations'] if
            row['address'] == capture['address'] and row['block_number'] == capture['block_number'])
        if capture['evidence_source']['kind'] == 'fresh_phase13':
            record = ledger[capture['evidence_source']['request_ordinal'] - 1]
            folder = attempt
        else:
            record = planned['reused_record']
            folder = WORK / 'phase10_lifi_private/factory_continuation_attempt1'
        req, res = folder / record['request_file'], folder / record['response_file']
        assert sha(req) == record['request_sha256'] and sha(res) == record['response_sha256']
        assert proposed['response_sha256'] == sha(res)
        request, response = read(req)['json'], read(res)
        assert request['method'] == 'eth_getCode' and request['params'] == [capture['address'], hex(capture['block_number'])]
        assert response['id'] == request['id'] and 'error' not in response
        raw = bytes.fromhex(response['result'][2:])
        assert hashlib.sha256(raw).hexdigest() == capture['runtime_sha256'] and len(raw) == capture['runtime_bytes']
        exact = [name for name, compiled in sorted(eligible.items()) if raw == compiled]
        assert exact == proposed['exact_matching_compiled_contracts']
        assert proposed['full_bytes_equal'] == bool(exact)
        assert proposed['equality_includes_metadata'] is True and proposed['masked_bytes'] == 0
        if exact:
            matches.append({'address': capture['address'], 'block_number': capture['block_number'],
                'checkpoint': capture['checkpoint'], 'compiled_contracts': exact})
    addresses = {x['address'] for x in observations}
    matched_addresses = {x['address'] for x in matches}
    assert table['unique_observed_addresses'] == len(addresses) == 14
    assert table['exact_match_observation_count'] == len(matches) == 11
    assert table['exact_match_unique_addresses'] == len(matched_addresses) == 6
    assert table['unique_observed_full_runtime_digests'] == len({x['runtime_sha256'] for x in observations})
    for key in ('new_compiler_invocations', 'new_network_requests', 'settings_searches', 'masked_bytes', 'new_case_admissions', 'detector_scores'):
        assert table[key] == 0
    original_cbridge = '0x73a499e043b03fc047189ab1ba72eb595ff1fc8e'
    assert original_cbridge in matched_addresses
    result = {'schema_version': 'article2_phase13_independent_retained_runtime_match_audit_v1',
        'status': 'PASS_ALL_RETAINED_FULL_RUNTIME_BYTE_COMPARISONS',
        'audited_utc': datetime.now(timezone.utc).isoformat(), 'auditor_sha256': sha(Path(__file__)),
        'comparison_table_sha256': sha(table_path), 'comparison_program_sha256': inputs['comparison_program_sha256'],
        'prior_compiler_output_sha256': sha(compiler_path), 'actual_capture_audit_sha256': sha(PHASE / 'qa/independent_actual_review.json'),
        'compiled_contracts': 59, 'source_paths': 44, 'nonempty_full_runtime_candidates': 36,
        'empty_outputs_excluded': 23, 'missing_or_nonhex_outputs': 0,
        'full_byte_comparisons': 684, 'sampled_address_checkpoint_pairs': 19,
        'exact_match_observations': 11, 'exact_match_addresses': 6,
        'additional_source_runtime_bound_addresses_beyond_prior_cbridge': len(matched_addresses - {original_cbridge}),
        'nonmatching_addresses': sorted(addresses - matched_addresses), 'matched_observations': matches,
        'metadata_masking_or_settings_search': False, 'producer_module_imported': False,
        'new_compiler_invocations_by_auditor': 0, 'new_network_requests_by_auditor': 0,
        'limitations': ['Only sampled returned bytes are bound; continuity and full historical routing remain unresolved.',
            'This reuses a previously independently reproduced same-compiler output, not compiler diversity.',
            'The candidate inventory was retained earlier and compared retrospectively after acquisition.',
            'A nonmatch is not a claim of semantic difference, missing source, maliciousness or case exclusion.',
            'No new source fetch or compilation was performed; original full compiler artifacts remain private.']}
    output = PHASE / 'qa/independent_runtime_match_review.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'path': str(output), 'sha256': sha(output),
        'matched_pairs': len(matches), 'matched_addresses': len(matched_addresses)}))


if __name__ == '__main__':
    main()
