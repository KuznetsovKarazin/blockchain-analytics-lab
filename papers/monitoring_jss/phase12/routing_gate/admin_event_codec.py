"""Strict canonical ABI decoding of the three frozen administrative event shapes.

This module classifies shape, not authorization, emitter source identity or
historical completeness. Inited is deliberately not attributed to one facet.
"""
import re


ZERO = "0x" + "00" * 20


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def hx(value, length=None):
    need(isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is not None, "Malformed byte hex")
    raw = bytes.fromhex(value[2:])
    need(length is None or len(raw) == length, "Wrong byte length")
    return raw


def word(value):
    need(type(value) is int and 0 <= value < 2**256, "Word outside uint256")
    return value.to_bytes(32, "big")


def address_word(value):
    return bytes(12) + hx(value, 20)


def read_word(data, offset):
    need(type(offset) is int and offset >= 0 and offset % 32 == 0 and offset + 32 <= len(data), "ABI word out of bounds/alignment")
    return data[offset:offset + 32]


def read_uint(data, offset):
    return int.from_bytes(read_word(data, offset), "big")


def decode_address(raw):
    need(len(raw) == 32 and raw[:12] == bytes(12), "Noncanonical ABI address padding")
    return "0x" + raw[12:].hex()


def encode_cut(cuts, initializer, calldata):
    tuples = []
    for cut in cuts:
        selectors = b"".join(hx(x, 4) + bytes(28) for x in cut["selectors"])
        tuples.append(address_word(cut["facet"]) + word(cut["action"]) + word(96)
                      + word(len(cut["selectors"])) + selectors)
    offsets, offset = [], 32 * len(tuples)
    for item in tuples:
        offsets.append(word(offset))
        offset += len(item)
    array = word(len(tuples)) + b"".join(offsets) + b"".join(tuples)
    raw = hx(calldata)
    tail = word(len(raw)) + raw + bytes((-len(raw)) % 32)
    return word(96) + address_word(initializer) + word(96 + len(array)) + array + tail


def decode_cut(data, caps):
    need(len(data) >= 128 and len(data) % 32 == 0, "Malformed DiamondCut head/length")
    array_start, initializer, calldata_start = read_uint(data, 0), decode_address(read_word(data, 32)), read_uint(data, 64)
    count = read_uint(data, array_start)
    need(count <= caps["max_cut_entries_per_event"], "DiamondCut entry cap")
    base, cuts, total_selectors = array_start + 32, [], 0
    for index in range(count):
        at = base + read_uint(data, base + 32 * index)
        facet, action = decode_address(read_word(data, at)), read_uint(data, at + 32)
        need(action <= 2, "DiamondCut action outside enum")
        selectors_at = at + read_uint(data, at + 64)
        selector_count = read_uint(data, selectors_at)
        total_selectors += selector_count
        need(total_selectors <= caps["max_selector_references_per_event"], "DiamondCut selector-reference cap")
        selectors = []
        for position in range(selector_count):
            encoded = read_word(data, selectors_at + 32 + 32 * position)
            need(encoded[4:] == bytes(28), "Noncanonical bytes4 ABI padding")
            selectors.append("0x" + encoded[:4].hex())
        cuts.append({"facet": facet, "action": action, "selectors": selectors})
    size = read_uint(data, calldata_start)
    need(size <= caps["max_initializer_calldata_bytes"] and calldata_start + 32 + size <= len(data), "Initializer calldata cap/bounds")
    calldata = "0x" + data[calldata_start + 32:calldata_start + 32 + size].hex()
    need(encode_cut(cuts, initializer, calldata) == data, "DiamondCut is not canonical complete ABI encoding")
    return {"event": "DiamondCut", "cuts": cuts, "initializer": initializer,
            "initializer_calldata": calldata, "initializer_effects_unclosed": initializer != ZERO or calldata != "0x"}


def decode_event(topics, data_hex, event_topics, caps):
    need(isinstance(topics, list) and bool(topics), "Missing event topics")
    topics = ["0x" + hx(x, 32).hex() for x in topics]
    data = hx(data_hex)
    need(len(data) <= caps["max_event_data_bytes"], "Event data cap")
    name = event_topics.get(topics[0])
    need(name is not None, "Unexpected event signature")
    if name == "DiamondCut":
        need(len(topics) == 1, "DiamondCut topic count")
        return decode_cut(data, caps)
    if name == "OwnershipTransferred":
        need(len(topics) == 3 and data == b"", "OwnershipTransferred topic/data shape")
        return {"event": name, "previous_owner": decode_address(hx(topics[1], 32)),
                "new_owner": decode_address(hx(topics[2], 32))}
    need(name == "Inited" and len(topics) == 2 and len(data) == 32, "Inited topic/data shape")
    chain = int.from_bytes(data, "big")
    need(chain < 2**64, "Inited uint64 padding")
    return {"event": name, "bridge": decode_address(hx(topics[1], 32)), "chain_id": chain,
            "facet_attribution": "AMBIGUOUS_SHARED_EVENT_SIGNATURE"}


class EventImpliedRegistry:
    """Source-shaped event replay; hidden writes/initializers are not modeled."""
    def __init__(self, diamond, max_facets, max_selectors):
        self.diamond, self.max_facets, self.max_selectors = diamond, max_facets, max_selectors
        self.owner, self.facets, self.selectors = ZERO, [], {}
        self.by_facet = {}

    def add_facet(self, facet):
        if facet not in self.by_facet:
            need(len(self.facets) < self.max_facets, "Replay facet cap")
            self.facets.append(facet)
            self.by_facet[facet] = []

    def remove(self, selector):
        need(selector in self.selectors, "Removal of selector absent from event-implied state")
        facet, position = self.selectors[selector]
        need(facet != self.diamond, "Removal of diamond immutable selector")
        values = self.by_facet[facet]
        last = values[-1]
        values[position] = last
        self.selectors[last] = (facet, position)
        values.pop()
        del self.selectors[selector]
        if not values:
            at = self.facets.index(facet)
            self.facets[at] = self.facets[-1]
            self.facets.pop()
            del self.by_facet[facet]

    def apply(self, event):
        name = event["event"]
        if name == "OwnershipTransferred":
            need(event["previous_owner"] == self.owner, "Ownership previous value differs from event-implied state")
            self.owner = event["new_owner"]
        elif name == "DiamondCut":
            need((event["initializer"] == ZERO) == (event["initializer_calldata"] == "0x"), "Initializer source precondition differs")
            for cut in event["cuts"]:
                facet, action, selectors = cut["facet"], cut["action"], cut["selectors"]
                need(bool(selectors), "Empty selector cut differs from source precondition")
                need((action == 2) == (facet == ZERO), "Cut facet zero/nonzero source precondition differs")
                if action != 2:
                    self.add_facet(facet)
                for selector in selectors:
                    if action == 0:
                        need(selector not in self.selectors, "Add selector already present in event-implied state")
                    elif action == 1:
                        need(selector in self.selectors and self.selectors[selector][0] != facet, "Replace old selector/facet differs")
                        self.remove(selector)
                    else:
                        self.remove(selector)
                        continue
                    need(len(self.selectors) < self.max_selectors, "Replay selector cap")
                    self.selectors[selector] = (facet, len(self.by_facet[facet]))
                    self.by_facet[facet].append(selector)
        # Inited intentionally changes no CBridge or other namespace state.

    def snapshot(self):
        return {"owner": self.owner, "facets": [{"address": facet, "facet_position": index,
                "selectors": list(self.by_facet[facet])} for index, facet in enumerate(self.facets)],
                "selector_map": {selector: {"facet": value[0], "selector_position": value[1]}
                                 for selector, value in sorted(self.selectors.items())}}
