"""Compile an owned, never-deployed layout probe importing frozen Li.Fi types.

Full input/source/AST stay private. This emits layout facts and slot formulas,
not historical values, runtime behavior, cryptographic proofs or routing history.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import re
import resource
import subprocess
import time
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'Duplicate JSON key: ' + k)
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def abi_type(field):
    return '(' + ','.join(abi_type(x) for x in field['components']) + ')' + field['type'][5:] if field['type'].startswith('tuple') else field['type']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', required=True, type=Path)
    p.add_argument('--acceptance', required=True, type=Path)
    p.add_argument('--probe', required=True, type=Path)
    p.add_argument('--source-response', required=True, type=Path)
    p.add_argument('--original-input', required=True, type=Path)
    p.add_argument('--original-output', required=True, type=Path)
    p.add_argument('--solc', required=True, type=Path)
    p.add_argument('--keccak-module', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    plan_raw, acceptance_raw = a.plan.read_bytes(), a.acceptance.read_bytes()
    plan, acceptance = strict_json(plan_raw), strict_json(acceptance_raw)
    runner_raw, probe_raw = Path(__file__).read_bytes(), a.probe.read_bytes()
    require(acceptance['plan_sha256'] == sha(plan_raw) and acceptance['runner_sha256'] == sha(runner_raw), 'Acceptance mismatch')
    require(acceptance['probe_sha256'] == sha(probe_raw) == plan['probe_sha256'], 'Probe binding mismatch')
    require(not a.output.exists(), 'Output exists; immutable attempts must not be overwritten')
    started_utc = stamp()
    accepted = datetime.datetime.fromisoformat(acceptance['accepted_at_utc'].replace('Z', '+00:00'))
    require(accepted.tzinfo is not None and accepted <= datetime.datetime.fromisoformat(started_utc), 'Acceptance must precede execution')
    a.output.mkdir(parents=True)
    for name, raw in [('plan.json', plan_raw), ('acceptance.json', acceptance_raw), ('runner.py', runner_raw), ('NamespaceLayoutProbe.sol', probe_raw)]:
        (a.output / name).write_bytes(raw)
    result = {'schema': 'article2_phase12_imported_storage_layout_v1', 'status': 'INCOMPLETE',
              'plan_sha256': sha(plan_raw), 'runner_sha256': sha(runner_raw), 'probe_sha256': sha(probe_raw),
              'accepted_at_utc': acceptance['accepted_at_utc'], 'started_utc': started_utc, 'invocations': [],
              'compiler_sha256': plan['compiler_sha256'], 'compiler_invocations': 0, 'version_probes': 0,
              'network_requests': 0, 'new_chain_payloads': 0, 'probe_deployed': False,
              'historical_routing_proved': False, 'detector_scores': 0, 'bindings': {}}
    try:
        def bound(label, path, digest):
            raw = path.read_bytes()
            require(sha(raw) == digest, 'Hash mismatch: ' + label)
            result['bindings'][label] = {'sha256': digest, 'bytes': len(raw)}
            return raw
        source = strict_json(bound('source_response', a.source_response, plan['source_response_sha256']))
        old_input = strict_json(bound('original_compiler_input', a.original_input, plan['original_input_sha256']))
        old_output = strict_json(bound('original_compiler_output', a.original_output, plan['original_output_sha256']))
        bound('compiler', a.solc, plan['compiler_sha256'])
        bound('keccak_implementation', a.keccak_module, plan['keccak_module_sha256'])
        spec = importlib.util.spec_from_file_location('layout_keccak', a.keccak_module)
        km = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(km)
        digest = km.digest256
        texts = {source['file_path']: source['source_code']}
        for item in source['additional_sources']:
            require(item['file_path'] not in texts, 'Duplicate source path')
            texts[item['file_path']] = item['source_code']
        require(len(texts) == 44, 'Unexpected original source count')
        require(old_input['language'] == 'Solidity' and old_input['sources'] == {k: {'content': v} for k, v in texts.items()}, 'Original input does not exactly contain retained sources')
        settings = copy.deepcopy(source['compiler_settings'])
        original_settings = copy.deepcopy(old_input['settings'])
        require('outputSelection' in original_settings, 'Original output selection absent')
        del original_settings['outputSelection']
        require(original_settings == settings and 'outputSelection' not in settings, 'Original settings mismatch')
        for name, text in texts.items():
            require(not name.startswith('/') and '..' not in Path(name).parts and '://' not in name, 'Unsafe source unit path')
            for node in old_output['sources'][name]['ast']['nodes']:
                if node['nodeType'] == 'ImportDirective':
                    require(node['absolutePath'] in texts, 'Original import closure incomplete')
        def constant(source_path, contract_name, name, expected):
            contracts = [n for n in old_output['sources'][source_path]['ast']['nodes'] if n['nodeType'] == 'ContractDefinition' and n['name'] == contract_name]
            require(len(contracts) == 1, 'AST contract identity')
            nodes = [n for n in contracts[0]['nodes'] if n['nodeType'] == 'VariableDeclaration' and n['name'] == name]
            require(len(nodes) == 1 and nodes[0]['constant'] is True, 'AST constant identity')
            value = nodes[0]['value']
            require(value['nodeType'] == 'FunctionCall' and value['expression']['name'] == 'keccak256', 'AST namespace expression')
            require(len(value['arguments']) == 1 and value['arguments'][0]['nodeType'] == 'Literal' and value['arguments'][0]['value'] == expected, 'AST namespace literal')
            return '0x' + digest(expected.encode()).hex()
        diamond_ns = constant('src/Libraries/LibDiamond.sol', 'LibDiamond', 'DIAMOND_STORAGE_POSITION', 'diamond.standard.diamond.storage')
        cbridge_ns = constant('src/Facets/CBridgeFacet.sol', 'CBridgeFacet', 'NAMESPACE', 'com.lifi.facets.cbridge2')
        probe_path = plan['probe_source_unit']
        require(probe_path not in texts, 'Probe path collides with retained source')
        settings['outputSelection'] = {probe_path: {'NamespaceLayoutProbe': ['storageLayout']}}
        inputs = {'language': 'Solidity', 'sources': {**{k: {'content': v} for k, v in texts.items()}, probe_path: {'content': probe_raw.decode('utf-8')}}, 'settings': settings}
        input_raw = (json.dumps(inputs, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(len(input_raw) <= plan['limits']['input_bytes'], 'Input byte cap exceeded')
        (a.output / 'compiler_input.json').write_bytes(input_raw)
        work = a.output / 'empty_compiler_cwd'
        work.mkdir()
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (plan['limits']['address_space_bytes'],) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (plan['limits']['cpu_seconds'],) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (plan['limits']['output_bytes'],) * 2)
        def finish_invocation(receipt, clock_start, stdout_name, stderr_name):
            receipt['completed_utc'] = stamp()
            receipt['elapsed_seconds'] = time.monotonic() - clock_start
            for kind, name in [('stdout', stdout_name), ('stderr', stderr_name)]:
                path = a.output / name
                if path.exists():
                    raw = path.read_bytes()
                    receipt[kind] = {'filename': name, 'bytes': len(raw), 'sha256': sha(raw)}
                else:
                    receipt[kind] = {'filename': name, 'exists': False}
            result['invocations'].append(receipt)
            write_json(a.output / (receipt['kind'] + '_invocation.json'), receipt)
        version_receipt = {'kind': 'version', 'started_utc': stamp(), 'returncode': None, 'exception': None}
        version_start = time.monotonic()
        result['version_probes'] = 1
        try:
            version = subprocess.run([str(a.solc.resolve()), '--version'], capture_output=True, timeout=10, cwd=work)
            version_receipt['returncode'] = version.returncode
            (a.output / 'compiler_version_stdout.txt').write_bytes(version.stdout)
            (a.output / 'compiler_version_stderr.txt').write_bytes(version.stderr)
        except Exception as exc:
            version_receipt['exception'] = type(exc).__name__ + ': ' + str(exc)
            if isinstance(exc, subprocess.TimeoutExpired):
                (a.output / 'compiler_version_stdout.txt').write_bytes(exc.stdout or b'')
                (a.output / 'compiler_version_stderr.txt').write_bytes(exc.stderr or b'')
            raise
        finally:
            finish_invocation(version_receipt, version_start, 'compiler_version_stdout.txt', 'compiler_version_stderr.txt')
        require(version.returncode == 0 and plan['compiler_version'] in version.stdout.decode(), 'Compiler version mismatch')
        compile_receipt = {'kind': 'compile', 'started_utc': stamp(), 'returncode': None, 'exception': None,
                           'compiler_input_sha256': sha(input_raw)}
        compile_start = time.monotonic()
        result['compiler_invocations'] = 1
        try:
            with (a.output / 'compiler_stdout.json').open('wb') as stdout, (a.output / 'compiler_stderr.txt').open('wb') as stderr:
                run = subprocess.run([str(a.solc.resolve()), '--standard-json'], input=input_raw, stdout=stdout, stderr=stderr,
                                     cwd=work, timeout=plan['limits']['wall_seconds'], preexec_fn=limits, check=False)
            compile_receipt['returncode'] = run.returncode
        except Exception as exc:
            compile_receipt['exception'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            finish_invocation(compile_receipt, compile_start, 'compiler_stdout.json', 'compiler_stderr.txt')
        output_raw = (a.output / 'compiler_stdout.json').read_bytes()
        require(len(output_raw) <= plan['limits']['output_bytes'], 'Compiler output byte cap exceeded')
        output = strict_json(output_raw)
        require(run.returncode == 0 and not any(x.get('severity') == 'error' for x in output.get('errors', [])), 'Probe compilation failed')
        layout = output['contracts'][probe_path]['NamespaceLayoutProbe']['storageLayout']
        write_json(a.output / 'layout_only.json', layout)
        types = layout['types']
        def typ(type_id):
            return types[type_id]
        def member_map(type_id):
            return {x['label']: x for x in typ(type_id)['members']}
        def check_member(member, slot, offset, label, size, encoding='inplace'):
            t = typ(member['type'])
            require(int(member['slot']) == slot and member['offset'] == offset, 'Member slot or offset differs: ' + member['label'])
            require(t['label'] == label and int(t['numberOfBytes']) == size and t['encoding'] == encoding, 'Member type differs: ' + member['label'])
        roots = {x['label']: x for x in layout['storage']}
        require(set(roots) == {'diamond', 'cbridge', 'selectorPacking', 'facetAddressPacking'}, 'Probe root fields differ')
        check_member(roots['diamond'], 0, 0, 'struct LibDiamond.DiamondStorage', 160)
        check_member(roots['cbridge'], 5, 0, 'struct CBridgeFacet.Storage', 32)
        ds, cs = member_map(roots['diamond']['type']), member_map(roots['cbridge']['type'])
        require(list(ds) == ['selectorToFacetAndPosition', 'facetFunctionSelectors', 'facetAddresses', 'supportedInterfaces', 'contractOwner'], 'Diamond member order')
        require(list(cs) == ['cBridge', 'cBridgeChainId'], 'CBridge member order')
        for name, slot in [('selectorToFacetAndPosition', 0), ('facetFunctionSelectors', 1), ('supportedInterfaces', 3)]:
            m = ds[name]
            require(int(m['slot']) == slot and m['offset'] == 0 and typ(m['type'])['encoding'] == 'mapping', 'Mapping base slot')
        check_member(ds['facetAddresses'], 2, 0, 'address[]', 32, 'dynamic_array')
        check_member(ds['contractOwner'], 4, 0, 'address', 20)
        check_member(cs['cBridge'], 0, 0, 'address', 20)
        check_member(cs['cBridgeChainId'], 0, 20, 'uint64', 8)
        sm, fm, im = [typ(ds[n]['type']) for n in ['selectorToFacetAndPosition', 'facetFunctionSelectors', 'supportedInterfaces']]
        require(typ(sm['key'])['label'] == 'bytes4' and int(typ(sm['key'])['numberOfBytes']) == 4, 'Selector mapping key')
        require(typ(fm['key'])['label'] == 'address' and int(typ(fm['key'])['numberOfBytes']) == 20, 'Facet mapping key')
        require(typ(im['key'])['label'] == 'bytes4' and typ(im['value'])['label'] == 'bool', 'Interface mapping types')
        sv, fv = member_map(sm['value']), member_map(fm['value'])
        require(list(sv) == ['facetAddress', 'functionSelectorPosition'] and list(fv) == ['functionSelectors', 'facetAddressPosition'], 'Mapping value struct fields')
        check_member(sv['facetAddress'], 0, 0, 'address', 20)
        check_member(sv['functionSelectorPosition'], 0, 20, 'uint96', 12)
        check_member(fv['functionSelectors'], 0, 0, 'bytes4[]', 32, 'dynamic_array')
        check_member(fv['facetAddressPosition'], 1, 0, 'uint256', 32)
        selector_array = typ(fv['functionSelectors']['type'])
        facet_array = typ(ds['facetAddresses']['type'])
        require(typ(selector_array['base'])['label'] == 'bytes4' and int(typ(selector_array['base'])['numberOfBytes']) == 4, 'Selector array element width')
        require(typ(facet_array['base'])['label'] == 'address' and int(typ(facet_array['base'])['numberOfBytes']) == 20, 'Facet array element width')
        check_member(roots['selectorPacking'], 6, 0, 'bytes4[9]', 64)
        check_member(roots['facetAddressPacking'], 8, 0, 'address[2]', 64)
        events = []
        for path, cname, event_name in [('src/Interfaces/IDiamondCut.sol', 'IDiamondCut', 'DiamondCut'), ('src/Libraries/LibDiamond.sol', 'LibDiamond', 'OwnershipTransferred'), ('src/Facets/CBridgeFacet.sol', 'CBridgeFacet', 'Inited')]:
            abi = old_output['contracts'][path][cname]['abi']
            entries = [x for x in abi if x['type'] == 'event' and x['name'] == event_name]
            require(len(entries) == 1 and entries[0]['anonymous'] is False, 'Event ABI identity')
            e = entries[0]
            sig = event_name + '(' + ','.join(abi_type(x) for x in e['inputs']) + ')'
            expected = plan['events'][event_name]
            require(sig == expected['signature'] and [x['indexed'] for x in e['inputs']] == expected['indexed'], 'Event ABI fields differ')
            events.append({'name': event_name, 'signature': sig, 'topic0': '0x' + digest(sig.encode()).hex(),
                           'indexed_fields': [x['name'] for x in e['inputs'] if x['indexed']],
                           'fields': [{'name': x['name'], 'canonical_type': abi_type(x), 'indexed': x['indexed']} for x in e['inputs']]})
        result.update(status='COMPILER_CONFIRMED_LAYOUT_READY_FOR_INDEPENDENT_REVIEW',
            achieved_evidence_tier='synthetic_storage_layout_importing_exact_target_source_types',
            probe_input_sha256=sha(input_raw), probe_output_sha256=sha(output_raw),
            source_file_count=44, probe_source_count=1, output_selection=['storageLayout'],
            diamond_namespace_hex=diamond_ns, cbridge_namespace_hex=cbridge_ns,
            delegated_storage_context={'address': '0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1', 'role': 'diamond',
                'applies_to': ['diamond_namespace', 'cbridge_namespace'],
                'caveat': 'CBridge packed fields are source-guided interpretations at diamond storage, not effective bridge configuration unless the corresponding facet/routing is independently bound active at the checkpoint.'},
            namespace_derivation='Pinned Keccak of the exact namespace literals in phase11 compiler AST; synthetic struct root slots are not actual deployed namespace roots.',
            diamond_fields={'selector_mapping': 0, 'facet_mapping': 1, 'facet_addresses': 2, 'supported_interfaces': 3, 'owner': 4},
            selector_mapping_value={'facet_address': {'byte_offset': 0, 'bytes': 20}, 'selector_position': {'byte_offset': 20, 'bytes': 12}},
            facet_struct={'selectors_length_slot': 0, 'facet_position_slot': 1},
            bytes4_array={'element_bytes': 4, 'elements_per_word': 8, 'slot_formula': 'keccak256(word(length_slot))+floor(i/8) mod2^256', 'bit_offset_formula': '32*(i%8)', 'element_type': 'bytes4, not uint32; decoding uses the same32-bit width'},
            address_array={'element_bytes': 20, 'elements_per_word': 1, 'slot_formula': 'keccak256(word(length_slot))+i mod2^256', 'bit_offset': 0},
            mapping_key_encoding={'bytes4': 'four key bytes followed by28zero bytes', 'address': '12zero bytes followed by20address bytes', 'formula': 'keccak256(padded_key||word(mapping_base))'},
            cbridge_word={'bridge': {'byte_offset': 0, 'bytes': 20}, 'chain_id': {'byte_offset': 20, 'bytes': 8}, 'undeclared_high_bytes': 4},
            layout_witness={'diamond_struct_bytes': 160, 'cbridge_struct_bytes': 32, 'bytes4_9_array_bytes': 64, 'address_2_array_bytes': 64},
            events=events, independent_formula_review='PENDING_SEPARATE_REVIEW',
            limitations=['Probe is synthetic and never deployed; actual namespace pointers are tied through retained source/AST, not by a state query.',
                         'storageLayout confirms types, member offsets, widths and fixed-array spans; mapping key padding and dynamic-array slot formulas still require independent semantic review, not an invented compiler layout field.',
                         'No actual historical slot values, complete writer set, selector activation, cryptographic proof or routing continuity is established.',
                         'Event topic filtering names intended administrative signatures; it does not prove event exhaustiveness or exclude post-event initializer writes.'])
    except Exception as exc:
        result.update(status='UNRESOLVED_LAYOUT_PROBE_FAILURE', detail=type(exc).__name__ + ': ' + str(exc))
    result['completed_utc'] = stamp()
    write_json(a.output / 'result.json', result)
    print(json.dumps({k: result[k] for k in ['status', 'compiler_invocations', 'version_probes', 'network_requests']}))
    if result['status'] != 'COMPILER_CONFIRMED_LAYOUT_READY_FOR_INDEPENDENT_REVIEW':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
