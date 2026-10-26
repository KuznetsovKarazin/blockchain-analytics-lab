"""Independent canonical ABI reader and list-based nominal registry model.

Only retained data is consumed. This does not prove event completeness, source
authorization, initializer effects, or continuous routing.
"""
import copy
import re

ZERO = '0x' + '00' * 20


def raw_hex(value, size=None):
    assert isinstance(value, str) and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value)
    value = bytes.fromhex(value[2:])
    assert size is None or len(value) == size
    return value


def abi_address(word):
    assert len(word) == 32 and word[:12] == bytes(12)
    return '0x' + word[12:].hex()


def decode(topics, value, signatures, caps):
    topics = [raw_hex(t, 32) for t in topics]
    assert topics
    name = signatures['0x' + topics[0].hex()]
    data = raw_hex(value)
    assert len(data) <= caps['max_event_data_bytes']
    if name == 'OwnershipTransferred':
        assert len(topics) == 3 and not data
        return {'event': name, 'previous_owner': abi_address(topics[1]), 'new_owner': abi_address(topics[2])}
    if name == 'Inited':
        assert len(topics) == 2 and len(data) == 32
        number = int.from_bytes(data, 'big')
        assert number < 2**64
        return {'event': name, 'bridge': abi_address(topics[1]), 'chain_id': number,
                'facet_attribution': 'AMBIGUOUS_SHARED_EVENT_SIGNATURE'}
    assert name == 'DiamondCut' and len(topics) == 1 and len(data) >= 160 and len(data) % 32 == 0
    def word(at):
        assert type(at) is int and at >= 0 and at % 32 == 0 and at + 32 <= len(data)
        return data[at:at + 32]
    def integer(at):
        return int.from_bytes(word(at), 'big')
    assert integer(0) == 96
    initializer, tail_at = abi_address(word(32)), integer(64)
    count = integer(96)
    assert count <= caps['max_cut_entries_per_event']
    offsets_base, cursor, cuts, total = 128, 128 + count * 32, [], 0
    for i in range(count):
        assert integer(offsets_base + i * 32) == cursor - offsets_base
        target, action = abi_address(word(cursor)), integer(cursor + 32)
        assert action in (0, 1, 2) and integer(cursor + 64) == 96
        n = integer(cursor + 96)
        total += n
        assert total <= caps['max_selector_references_per_event']
        selectors = []
        for j in range(n):
            selector = word(cursor + 128 + j * 32)
            assert selector[4:] == bytes(28)
            selectors.append('0x' + selector[:4].hex())
        cuts.append({'facet': target, 'action': action, 'selectors': selectors})
        cursor += 128 + n * 32
    assert cursor == tail_at
    size = integer(cursor)
    assert size <= caps['max_initializer_calldata_bytes']
    cursor += 32
    padded_size = (size + 31) // 32 * 32
    assert cursor + padded_size == len(data)
    assert data[cursor + size:] == bytes(padded_size - size)
    calldata = '0x' + data[cursor:cursor + size].hex()
    return {'event': name, 'cuts': cuts, 'initializer': initializer, 'initializer_calldata': calldata,
            'initializer_effects_unclosed': initializer != ZERO or calldata != '0x'}


class Registry:
    """List-based model; no producer class or source code is imported."""
    def __init__(self, checkpoint, diamond, facet_cap, selector_cap):
        self.owner = checkpoint['owner']
        self.facets = [{key: copy.deepcopy(facet[key]) for key in ('address', 'facet_position', 'selectors')}
                       for facet in checkpoint['enumerated_facets']]
        self.diamond, self.facet_cap, self.selector_cap = diamond, facet_cap, selector_cap
        self.validate()

    def validate(self):
        assert len(self.facets) <= self.facet_cap
        assert len({x['address'] for x in self.facets}) == len(self.facets)
        selectors = []
        for i, facet in enumerate(self.facets):
            facet['facet_position'] = i
            assert facet['selectors']
            selectors += facet['selectors']
        assert len(selectors) == len(set(selectors)) <= self.selector_cap

    def locate(self, selector):
        matches = [(i, x['selectors'].index(selector)) for i, x in enumerate(self.facets) if selector in x['selectors']]
        assert len(matches) <= 1
        return matches[0] if matches else None

    def remove(self, selector):
        found = self.locate(selector)
        assert found is not None
        i, j = found
        facet = self.facets[i]
        assert facet['address'] != self.diamond
        facet['selectors'][j] = facet['selectors'][-1]
        facet['selectors'].pop()
        if not facet['selectors']:
            self.facets[i] = self.facets[-1]
            self.facets.pop()

    def apply(self, event):
        trial = copy.deepcopy(self)
        trial._apply(event)
        trial.validate()
        self.owner, self.facets = trial.owner, trial.facets

    def _apply(self, event):
        if event['event'] == 'OwnershipTransferred':
            assert event['previous_owner'] == self.owner
            self.owner = event['new_owner']
        elif event['event'] == 'DiamondCut':
            assert (event['initializer'] == ZERO) == (event['initializer_calldata'] == '0x')
            for cut in event['cuts']:
                address, action = cut['facet'], cut['action']
                assert cut['selectors'] and ((action == 2) == (address == ZERO))
                if action != 2 and not any(f['address'] == address for f in self.facets):
                    assert len(self.facets) < self.facet_cap
                    self.facets.append({'address': address, 'facet_position': len(self.facets), 'selectors': []})
                for selector in cut['selectors']:
                    old = self.locate(selector)
                    if action == 0:
                        assert old is None
                    elif action == 1:
                        assert old is not None and self.facets[old[0]]['address'] != address
                        self.remove(selector)
                    else:
                        self.remove(selector)
                        continue
                    target = next(f for f in self.facets if f['address'] == address)
                    target['selectors'].append(selector)

    def snapshot(self):
        result = {'owner': self.owner, 'facets': copy.deepcopy(self.facets), 'selector_map': {}}
        for facet in self.facets:
            for i, selector in enumerate(facet['selectors']):
                result['selector_map'][selector] = {'facet': facet['address'], 'selector_position': i}
        result['selector_map'] = dict(sorted(result['selector_map'].items()))
        return result
