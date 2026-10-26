"""Offline, accepted-plan check of compiler-bound LiFi constructor receipt events.

No network or compiler execution. This is a two-event bootstrap check, not routing history.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import re
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('Duplicate JSON key: ' + key)
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def hx(value, length=None):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value) is not None, 'Malformed byte hex')
    raw = bytes.fromhex(value[2:])
    require(length is None or len(raw) == length, 'Wrong byte length')
    return raw


def address_word(raw):
    require(len(raw) == 32 and raw[:12] == bytes(12), 'Noncanonical ABI address')
    return '0x' + raw[12:].hex()


def uint(value):
    require(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value) is not None, 'Malformed RPC quantity')
    return int(value, 16)


def canonical_type(field):
    if field['type'].startswith('tuple'):
        return '(' + ','.join(canonical_type(x) for x in field['components']) + ')' + field['type'][5:]
    return field['type']


def signature(entry):
    return entry['name'] + '(' + ','.join(canonical_type(x) for x in entry['inputs']) + ')'


def one(abi, kind, name=None):
    entries = [x for x in abi if x['type'] == kind and (name is None or x.get('name') == name)]
    require(len(entries) == 1, 'ABI entry is missing or ambiguous')
    return entries[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--acceptance', required=True, type=Path)
    parser.add_argument('--retained-root', required=True, type=Path)
    parser.add_argument('--compilation-root', required=True, type=Path)
    parser.add_argument('--keccak-module', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    plan_raw, accept_raw = args.plan.read_bytes(), args.acceptance.read_bytes()
    plan, acceptance = strict_json(plan_raw), strict_json(accept_raw)
    require(acceptance['plan_sha256'] == sha(plan_raw), 'Plan acceptance mismatch')
    require(acceptance['runner_sha256'] == sha(Path(__file__).read_bytes()), 'Runner acceptance mismatch')
    require(acceptance['compilation_status'] == 'EXACT_SOURCE_COMPILER_BYTECODE_CONSISTENCY', 'Exact compilation not accepted')
    require(not args.output.exists(), 'Output already exists; do not overwrite')
    accepted_at = datetime.datetime.fromisoformat(acceptance['accepted_at_utc'].replace('Z', '+00:00'))
    args.output.mkdir(parents=True)
    (args.output / 'plan.json').write_bytes(plan_raw)
    (args.output / 'acceptance.json').write_bytes(accept_raw)
    (args.output / 'runner_source.py').write_bytes(Path(__file__).read_bytes())
    result = {'schema_version': 'article2_phase11_constructor_receipt_check_v1', 'status': 'INCOMPLETE',
              'plan_sha256': sha(plan_raw), 'runner_sha256': sha(Path(__file__).read_bytes()),
              'new_network_requests': 0, 'compiler_invocations': 0, 'detector_scores': 0,
              'scientific_admissions': 0, 'historical_routing_proved': False, 'input_bindings': {}}
    try:
        def load(label, path, expected):
            raw = path.read_bytes()
            require(sha(raw) == expected, 'Input hash mismatch: ' + path.name)
            require(label not in result['input_bindings'], 'Duplicate logical input label')
            result['input_bindings'][label] = {'filename': path.name, 'sha256': expected, 'bytes': len(raw)}
            return strict_json(raw)
        source = load('source_response', args.retained_root / plan['source']['relative_path'], plan['source']['sha256'])
        tx = load('creation_transaction', args.retained_root / plan['transaction']['relative_path'], plan['transaction']['sha256'])['result']
        receipt = load('creation_receipt', args.retained_root / plan['receipt']['relative_path'], plan['receipt']['sha256'])['result']
        historical = load('historical_summary', args.retained_root / plan['historical_summary']['relative_path'], plan['historical_summary']['sha256'])
        output = load('compiler_output', args.compilation_root / 'diamond/compiler_output.json', acceptance['compiler_output_sha256'])
        compilation = load('compilation_summary', args.compilation_root / 'summary.json', acceptance['compilation_summary_sha256'])
        require(compilation['all_exact'] is True and compilation['disposition'] == acceptance['compilation_status'], 'Producer exact compilation missing')
        completed = datetime.datetime.fromisoformat(compilation['completed_utc'].replace('Z', '+00:00'))
        require(completed <= accepted_at <= datetime.datetime.now(datetime.timezone.utc), 'Acceptance did not follow completed compilation')
        require(sha(args.keccak_module.read_bytes()) == plan['keccak_module_sha256'], 'Keccak implementation changed')
        spec = importlib.util.spec_from_file_location('bootstrap_keccak', args.keccak_module)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        digest = module.digest256
        require(not any(e.get('severity') == 'error' for e in output.get('errors', [])), 'Compiler errors')
        contract = output['contracts']['src/LiFiDiamond.sol']['LiFiDiamond']
        library = output['contracts']['src/Libraries/LibDiamond.sol']['LibDiamond']
        interface = output['contracts']['src/Interfaces/IDiamondCut.sol']['IDiamondCut']
        metadata = strict_json(contract['metadata'])
        require(metadata['compiler']['version'] == plan['compiler_version'], 'Compiler metadata version')
        source_set = {source['file_path']: source['source_code']}
        for entry in source['additional_sources']:
            require(entry['file_path'] not in source_set, 'Duplicate source path')
            source_set[entry['file_path']] = entry['source_code']
        require(set(metadata['sources']) == set(source_set), 'Metadata source set differs')
        for name, text in source_set.items():
            require(metadata['sources'][name]['keccak256'].lower() == '0x' + digest(text.encode('utf-8')).hex(), 'Metadata source hash differs')
        require(contract['evm']['bytecode'].get('linkReferences', {}) == {}, 'Creation linking unsupported')
        deployed = contract['evm']['deployedBytecode']
        require(deployed.get('linkReferences', {}) == {} and deployed.get('immutableReferences', {}) == {}, 'Runtime substitution unsupported')
        created_bytes = hx('0x' + contract['evm']['bytecode']['object'])
        runtime = hx('0x' + deployed['object'])
        require(runtime and runtime == hx(source['deployed_bytecode']), 'Full compiler/runtime mismatch')
        constructor = one(contract['abi'], 'constructor')
        require([x['type'] for x in constructor['inputs']] == ['address', 'address'], 'Constructor ABI types differ')
        require([x['name'] for x in constructor['inputs']] == ['_contractOwner', '_diamondCutFacet'], 'Constructor ABI roles differ')
        require(tx['hash'].lower() == receipt['transactionHash'].lower() == plan['creation_transaction'], 'Creation transaction binding')
        require(tx['to'].lower() == receipt['to'].lower() == plan['factory'], 'Factory recipient binding')
        require(tx['from'].lower() == receipt['from'].lower(), 'Sender binding')
        require(receipt['contractAddress'] is None and uint(receipt['status']) == 1, 'Expected successful factory receipt')
        target = next(x for x in historical['contracts'] if x['role'] == 'diamond')
        require(uint(tx['blockNumber']) == uint(receipt['blockNumber']) == target['creation_block'], 'Creation block binding')
        require(tx['blockHash'].lower() == receipt['blockHash'].lower() == target['creation_block_hash'], 'Creation block hash binding')
        require(uint(tx['transactionIndex']) == uint(receipt['transactionIndex']), 'Transaction position binding')
        factory_input = hx(tx['input'])
        require(len(factory_input) > 32, 'Factory input too short')
        initcode = factory_input[32:]
        require(initcode == hx(source['creation_bytecode']), 'Source/factory initcode differs')
        require(initcode.startswith(created_bytes), 'Compiled creation prefix differs')
        suffix = initcode[len(created_bytes):]
        require(len(suffix) == 64, 'Constructor suffix is not exactly two words')
        owner, facet = address_word(suffix[:32]), address_word(suffix[32:])
        func = one(interface['abi'], 'function', 'diamondCut')
        cut_event = one(interface['abi'], 'event', 'DiamondCut')
        owner_event = one(library['abi'], 'event', 'OwnershipTransferred')
        require(signature(func) == 'diamondCut((address,uint8,bytes4[])[],address,bytes)', 'Function ABI shape')
        require(signature(cut_event) == 'DiamondCut((address,uint8,bytes4[])[],address,bytes)', 'Cut event ABI shape')
        require(cut_event.get('anonymous') is False and [x['indexed'] for x in cut_event['inputs']] == [False, False, False], 'Cut event indexing')
        require(signature(owner_event) == 'OwnershipTransferred(address,address)', 'Owner event ABI shape')
        require(owner_event.get('anonymous') is False and [x['indexed'] for x in owner_event['inputs']] == [True, True], 'Owner event indexing')
        selector = digest(signature(func).encode())[:4]
        owner_topic, cut_topic = digest(signature(owner_event).encode()), digest(signature(cut_event).encode())
        logs = receipt['logs']
        require(isinstance(logs, list), 'Receipt logs malformed')
        log_indices = [uint(log['logIndex']) for log in logs]
        require(log_indices == sorted(set(log_indices)), 'Receipt logs unordered or duplicated')
        for log in logs:
            require(log.get('removed', False) is False, 'Removed log')
            require(log['transactionHash'].lower() == plan['creation_transaction'], 'Log transaction binding')
            require(log['blockHash'].lower() == receipt['blockHash'].lower(), 'Log block hash binding')
            require(uint(log['blockNumber']) == uint(receipt['blockNumber']), 'Log block number binding')
            require(uint(log['transactionIndex']) == uint(receipt['transactionIndex']), 'Log transaction position binding')
        own_logs = [log for log in logs if log['address'].lower() == plan['diamond']]
        require(len(own_logs) == 2, 'Expected exactly two diamond constructor logs')
        ownership, cut = own_logs
        require([hx(x, 32) for x in ownership['topics']] == [owner_topic, bytes(32), suffix[:32]], 'Ownership event differs from zero-to-constructor-owner')
        require(hx(ownership['data']) == b'', 'Ownership event data not empty')
        require([hx(x, 32) for x in cut['topics']] == [cut_topic], 'Cut topic differs')
        word = lambda x: x.to_bytes(32, 'big')
        expected_data = b''.join([word(96), bytes(32), word(320), word(1), word(32), suffix[32:], word(0), word(96), word(1), selector + bytes(28), word(0)])
        require(hx(cut['data']) == expected_data, 'Cut data not canonical one-facet Add/one-selector/zero-init/empty-calldata')
        result.update(status='PASS', achieved_evidence_tier='compiler_bound_constructor_receipt_consistency',
                      owner_at_constructor=owner, initial_diamond_cut_facet=facet,
                      constructor_suffix_bytes=64, constructor_arguments_from_source_annotations=False,
                      diamond_cut_selector='0x' + selector.hex(), cut_action='Add',
                      cut_initializer='0x' + bytes(20).hex(), cut_initializer_calldata='0x',
                      expected_diamond_events=2, other_emitter_event_count=len(logs)-2,
                      ownership_log_index=uint(ownership['logIndex']), cut_log_index=uint(cut['logIndex']),
                      canonical_cut_data_bytes=len(expected_data), full_runtime_bytes=len(runtime),
                      interpretation='Constructor bootstrap only. No initial facet runtime verification, later owner/selector/configuration history or full-window activation follows.')
    except Exception as exc:
        result.update(status='UNRESOLVED_VALIDATION_FAILURE', error=type(exc).__name__ + ': ' + str(exc))
    result['completed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['status', 'new_network_requests', 'historical_routing_proved']}))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
