#!/usr/bin/env python3
"""Focused arithmetic/projection check over already independently audited events.

No acquisition, old tests, ABI decoder or full registry replay is executed here.
"""
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def main():
    root = Path(__file__).resolve().parents[4]
    paper, work = root / 'papers/monitoring_jss', root.parent
    base = paper / 'phase14/archive_access'
    history_path, timeline_path, prose_path = base / 'history_findings.json', base / 'event_timeline.json', base / 'EVENT_HISTORY.md'
    assert sha(prose_path) == '30718f67534a2b94822828924e6950cd9a80e7e659e2ddad4ce2fff1d85d7854'
    history, timeline, prose = load(history_path), load(timeline_path), prose_path.read_text()
    audit_path = paper / 'phase14/qa/archive_access_actual_review.json'
    audit = load(audit_path)
    assert audit['status'] == 'PASS_INDEPENDENT_INDEXER_RECORDS_AND_NOMINAL_REPLAY'
    summary_path = work / 'phase14_lifi_private/blockscout_events_attempt1/summary.json'
    summary = load(summary_path)
    assert sha(summary_path) == audit['summary_sha256'] == history['summary_sha256']
    assert history['requests_sha256'] == audit['requests_sha256']
    checkpoints_path = work / 'phase12_lifi_private/checkpoint_only_attempt1/summary.json'
    assert sha(checkpoints_path) == timeline['prior_checkpoint_summary_sha256']
    states = {row['name']: row for row in load(checkpoints_path)['states']}
    initial, final = states['start']['selector_map'], states['end']['selector_map']
    endpoint_changed = {s for s in initial.keys() & final.keys() if initial[s]['facet'] != final[s]['facet']}
    active, counts = set(initial), [len(initial)]
    removed, replacements, readded, added = {}, [], [], []
    projected, rows, refs, entries = [], [], Counter(), Counter()
    for item in summary['events']:
        event = item['decoded']
        timestamp = item['timestamp_epoch_seconds']
        stamp = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        projected_row = {k: item[k] for k in ('block_hash', 'block_number', 'log_index', 'removed', 'transaction_hash', 'transaction_index')}
        projected_row['indexer_reported_timestamp_utc'] = stamp
        decoded = copy.deepcopy(event)
        calldata = bytes.fromhex(decoded.pop('initializer_calldata', '0x')[2:])
        actions = Counter()
        if event['event'] == 'DiamondCut':
            decoded.update(initializer_calldata_bytes=len(calldata),
                           initializer_calldata_selector='0x' + calldata[:4].hex() if len(calldata) >= 4 else None,
                           initializer_calldata_sha256=hashlib.sha256(calldata).hexdigest())
            for cut in event['cuts']:
                name = ['Add', 'Replace', 'Remove'][cut['action']]
                entries[name] += 1
                refs[name] += len(cut['selectors'])
                actions[name] += len(cut['selectors'])
                for selector in cut['selectors']:
                    if name == 'Remove':
                        assert selector in active
                        active.remove(selector)
                        removed[selector] = (item['block_number'], timestamp)
                    elif name == 'Replace':
                        assert selector in active and selector in endpoint_changed
                        replacements.append({'block': item['block_number'], 'new_facet': cut['facet'],
                                             'selector': selector, 'start_facet': initial[selector]['facet']})
                        assert final[selector]['facet'] == cut['facet']
                    else:
                        assert selector not in active
                        active.add(selector)
                        if selector in removed:
                            old_block, old_timestamp = removed.pop(selector)
                            assert selector in endpoint_changed
                            readded.append({'event_implied_gap_seconds': timestamp - old_timestamp,
                                            'gap_excludes_hidden_writer_effects': False,
                                            'new_facet': cut['facet'], 'readded_block': item['block_number'],
                                            'removed_block': old_block, 'selector': selector,
                                            'start_facet': initial[selector]['facet']})
                        else:
                            assert selector not in initial and selector in final
                            added.append({'block': item['block_number'], 'new_facet': cut['facet'], 'selector': selector})
                        assert final[selector]['facet'] == cut['facet']
        projected_row['decoded'] = decoded
        projected.append(projected_row)
        counts.append(counts[-1] + actions['Add'] - actions['Remove'])
        assert counts[-1] == len(active)
        rows.append({'add_selector_references': actions['Add'], 'block': item['block_number'],
                     'event': event['event'], 'initializer': event.get('initializer'),
                     'initializer_calldata_bytes': len(calldata), 'log_index': item['log_index'],
                     'nominal_selector_count_after': len(active), 'remove_selector_references': actions['Remove'],
                     'replace_selector_references': actions['Replace'], 'timestamp_utc': stamp,
                     'transaction_index': item['transaction_index']})
    assert history['events'] == projected and history['returned_selector_references_by_action'] == dict(refs)
    assert history['returned_cut_entries_by_action'] == dict(entries)
    assert history['retained_window_records'] == len(projected) == 8
    assert history['distinct_returned_event_transactions'] == len({row['transaction_hash'] for row in projected}) == 7
    assert history['distinct_returned_event_blocks'] == len({row['block_number'] for row in projected}) == 7
    for key in ('controls', 'completed_window_topics', 'disposition', 'elapsed_seconds', 'end_checkpoint_comparison',
                'event_type_counts', 'http_gets', 'retained_response_bytes', 'nonzero_initializer_event_count',
                'nominal_replay_performed', 'nominal_replay_events_applied', 'nominal_replay_error',
                'window_records_missing_block_hash', 'window_records_missing_removed_status',
                'window_schedule_complete_unsaturated', 'discovered_nonzero_facets', 'discovered_selectors',
                'plan_sha256', 'runner_sha256', 'authenticated_chain_mapping', 'historical_routing_proved',
                'index_completeness_proved', 'scientific_admissions', 'detector_scores'):
        assert history[key] == summary[key]
    assert history['failure_detail'] is None
    assert history['new_network_requests_by_projection'] == history['new_replay_executions_by_projection'] == 0
    targets = sorted({row['decoded']['initializer'] for row in projected if row['decoded'].get('initializer_effects_unclosed')})
    assert history['returned_initializer_targets'] == targets
    assert timeline['history_findings_sha256'] == sha(history_path)
    assert timeline['rows'] == rows and timeline['selector_counts_arithmetic'] == counts
    assert timeline['endpoint_changed_selectors_with_Replace_event'] == replacements
    assert timeline['endpoint_changed_selectors_with_remove_then_add_events'] == readded
    assert timeline['new_endpoint_selectors_added'] == added
    assert timeline['removed_without_returned_readdition'] == sorted(removed)
    assert active == set(final) and len(endpoint_changed) == 14
    assert {r['selector'] for r in replacements} | {r['selector'] for r in readded} == endpoint_changed
    assert not ({r['selector'] for r in replacements} & {r['selector'] for r in readded})
    assert timeline['unlogged_writers_or_initializer_effects_excluded'] is False
    assert dict(refs) == {'Add': 10, 'Replace': 9, 'Remove': 7}
    assert counts == [25, 20, 18, 23, 25, 26, 27, 27, 28]
    gaps = [row['event_implied_gap_seconds'] for row in readded]
    assert gaps == [45156, 45156, 45234, 45329, 45544]
    for row in rows:
        line = '| ' + row['timestamp_utc'][11:19] + ' | ' + format(row['block'], ',') + ' | ' + str(row['log_index'])
        line += ' | ' + row['event'] + ' | ' + str(row['remove_selector_references']) + ' | ' + str(row['replace_selector_references'])
        line += ' | ' + str(row['add_selector_references']) + ' | ' + str(row['nominal_selector_count_after']) + ' |'
        assert line in prose
    for row in projected:
        dec = row['decoded']
        if dec.get('initializer_effects_unclosed'):
            line = '| ' + format(row['block_number'], ',') + ' | `' + dec['initializer'] + '` | `' + dec['initializer_calldata_selector']
            line += '` | ' + format(dec['initializer_calldata_bytes'], ',') + ' |'
            assert line in prose
    bindings = load(paper / 'phase13/acquisition/runtime_match_table.json')['observations']
    assert all(not row['exact_matching_compiled_contracts'] for row in bindings if row['address'] == '0xe73b96b69870e9db5a5283e674f9fe62c89cc7a2')
    assert any(row['address'] == '0x8a017f915029e908bad589ef0f2af84d9dd4c976'
               and row['exact_matching_compiled_contracts'] == ['src/Facets/NXTPFacet.sol:NXTPFacet'] for row in bindings)
    assert 'whose source remained unbound in Phase13' in prose and 'NXTP' not in prose
    assert 'not independently verified periods of unavailable execution' in prose
    result = {'schema_version': 'article2_phase14_history_findings_review_v1',
              'status': 'PASS_DERIVED_EVENT_CHRONOLOGY_AND_SCOPE',
              'reviewed_utc': datetime.now(timezone.utc).isoformat(), 'reviewer_program_sha256': sha(Path(__file__)),
              'input_bindings': [{'path': str(p.relative_to(root)), 'sha256': sha(p)}
                                 for p in (history_path, timeline_path, prose_path, audit_path)],
              'actual_summary_sha256': sha(summary_path),
              'selector_action_references': dict(refs), 'cut_entries_by_action': dict(entries),
              'selector_counts': counts, 'endpoint_changed_selectors': len(endpoint_changed),
              'changed_by_replace': len(replacements), 'changed_by_remove_then_add': len(readded),
              'event_implied_gap_seconds': gaps, 'new_endpoint_selectors': len(added),
              'removed_not_readded_selectors': sorted(removed),
              'initializer_calldata_lengths': [r['decoded']['initializer_calldata_bytes'] for r in projected if r['decoded'].get('initializer_effects_unclosed')],
              'unbound_facet_label_corrected_and_checked': True,
              'intervals_claim_verified_execution_unavailability': False,
              'new_acquisition_requests': 0, 'old_suites_rerun': 0, 'abi_decoder_reruns': 0,
              'full_registry_replays': 0,
              'method': 'Independent cut-action/set arithmetic and projection checks over the exact already independently decoded event list. No producer summarizer imported.'}
    output = Path(__file__).with_suffix('.json')
    assert not output.exists()
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('status', 'selector_action_references', 'selector_counts', 'changed_by_replace', 'changed_by_remove_then_add')}))


if __name__ == '__main__':
    main()
