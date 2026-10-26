#!/usr/bin/env python3
"""Executable methodological boundary; supplied manifests still need auditing.

This pure routing aid never acquires data, computes a detector score, changes a
cohort or admits a case. Boolean assertions are not independent source evidence.
"""
import argparse
import json

FORBIDDEN_NOMINATION_BASES = ('victim_or_attacker_address_list', 'execution_flow_or_trace',
    'detector_score_or_alert', 'favorable_signal_or_warmup', 'modern_roster_without_historical_support')
REQUIRED_FREEZE_FIELDS = ('all_frame_dispositions_completed', 'cohort_order_frozen',
    'row_nomination_reviewed', 'historical_core_provenance_bound', 'nomination_exposure_recorded',
    'source_plan_and_limits_frozen', 'window_and_initialization_frozen', 'method_sources_and_parameters_bound',
    'positive_inventory_and_label_join_procedure_frozen', 'coverage_denominators_frozen',
    'method_relative_exposure_review_passed')


def premeasurement(state):
    """Determine readiness for a separately frozen future measurement, not admission."""
    if state.get('scope_amendment_accepted') is not True:
        return {'status': 'AMENDMENT_NOT_ACCEPTED', 'case_admitted': False}
    status = state.get('metadata_status')
    if status == 'DEVELOPMENT_EXCLUDED':
        return {'status': 'DEVELOPMENT_ONLY', 'case_admitted': False}
    if status == 'NOT_REALIZED_INCIDENT':
        return {'status': 'NOT_A_REALIZED_POSITIVE_CASE', 'case_admitted': False}
    if status != 'METADATA_READY_FOR_HISTORICAL_GATES':
        return {'status': 'METADATA_UNRESOLVED', 'case_admitted': False}
    forbidden = [key for key in FORBIDDEN_NOMINATION_BASES if state.get('nomination_basis', {}).get(key) is True]
    if forbidden:
        return {'status': 'NOMINATION_RULE_VIOLATION', 'reasons': forbidden, 'case_admitted': False}
    missing = [key for key in REQUIRED_FREEZE_FIELDS if state.get(key) is not True]
    if missing:
        return {'status': 'PENDING_PREMEASUREMENT_REQUIREMENTS', 'missing': missing, 'case_admitted': False}
    if state.get('initialization_rule') != 'independent_utc_day_reset':
        return {'status': 'SEPARATE_INITIALIZATION_AMENDMENT_REQUIRED', 'case_admitted': False}
    return {'status': 'READY_FOR_SEPARATELY_FROZEN_ACQUISITION', 'case_admitted': False,
        'qualification': 'Requires auditable exact manifests and root acceptance; not case admission or a performance result.'}


def coverage(state):
    """Classify one reference execution after decisions; never alter input selection."""
    if state.get('decisions_closed') is not True:
        return {'status': 'LABEL_JOIN_NOT_ALLOWED_YET', 'known_execution_denominator': None}
    if state.get('positive_execution_verified') is not True:
        return {'status': 'UNKNOWN_LABEL', 'known_execution_denominator': None}
    if state.get('source_coverage_verified') is not True:
        return {'status': 'UNAVAILABLE_OBSERVATION', 'known_execution_denominator': True,
            'measured_miss': None, 'coverage_rate_reportable_for_incomplete_set': False}
    if state.get('method') not in ('semantic', 'count'):
        return {'status': 'UNKNOWN_METHOD', 'known_execution_denominator': True, 'measured_miss': None}
    required = ['selected_core_emitter_transaction']
    if state.get('selected_core_emitter_transaction') is True:
        required.extend(['raw_trigger', 'group_candidate', 'emitted_notification'])
        if state['method'] == 'semantic':
            required.extend(['positive_core_external_outflow', 'minimum_history_available'])
    missing = [key for key in required if type(state.get(key)) is not bool]
    if missing:
        return {'status': 'COVERAGE_OR_DECISION_UNRESOLVED', 'missing': missing,
            'known_execution_denominator': True, 'measured_miss': None}
    if ((state.get('emitted_notification') is True and state.get('group_candidate') is not True)
        or (state.get('group_candidate') is True and state.get('raw_trigger') is not True)
        or (any(state.get(key) is True for key in ('raw_trigger', 'group_candidate', 'emitted_notification'))
            and state.get('selected_core_emitter_transaction') is not True)
        or (state.get('method') == 'semantic' and state.get('raw_trigger') is True
            and (state.get('positive_core_external_outflow') is not True
                 or state.get('minimum_history_available') is not True))):
        return {'status': 'INCONSISTENT_DECISION_EVIDENCE', 'known_execution_denominator': True, 'measured_miss': None}
    if state.get('selected_core_emitter_transaction') is not True:
        stage = 'NO_CORE_EMITTER_LOG'
    elif state.get('method') == 'semantic' and state.get('positive_core_external_outflow') is not True:
        stage = 'NO_POSITIVE_CORE_EXTERNAL_OUTFLOW'
    elif state.get('method') == 'semantic' and state.get('minimum_history_available') is not True:
        stage = 'COLD_START'
    elif state.get('raw_trigger') is not True:
        stage = 'NO_RAW_TRIGGER'
    elif state.get('group_candidate') is not True:
        stage = 'GROUPED_WITHOUT_SEPARATE_CANDIDATE'
    elif state.get('emitted_notification') is not True:
        stage = 'BUDGET_SUPPRESSED'
    else:
        stage = 'NOTIFIED'
    return {'status': stage, 'known_execution_denominator': True, 'measured_miss': stage != 'NOTIFIED',
        'miss_definition': 'No emitted notification on this verified reference execution under the fixed input scope; not a scored benign label.',
        'case_exclusion_allowed': False, 'population_expansion_allowed': False,
        'complete_incident_miss_established': False,
        'incident_limit': 'Aggregate only after checking the complete independent incident execution inventory; one execution is not one incident.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=('premeasurement', 'coverage'))
    parser.add_argument('state', help='JSON state with independently audited evidence bindings')
    args = parser.parse_args()
    with open(args.state, encoding='utf-8') as handle:
        value = json.load(handle)
    print(json.dumps((premeasurement if args.stage == 'premeasurement' else coverage)(value), indent=2))


if __name__ == '__main__':
    main()
