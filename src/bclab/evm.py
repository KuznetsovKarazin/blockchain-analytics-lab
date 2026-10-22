"""
Minimal EVM bytecode utilities for the Ponzi case study.

  opcodes(hex)        linear disassembly into mnemonics (PUSH operands skipped)
  strip_metadata(hex) remove the Solidity metadata trailer (swarm hash) so that
                      recompilations of the same source compare equal
  skeleton(hex)       hash of the opcode sequence without PUSH operands: groups
                      contracts that differ only in constants and addresses
"""

from __future__ import annotations

import hashlib
import re

_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
    0x08: "ADDMOD", 0x09: "MULMOD", 0x0a: "EXP", 0x0b: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR", 0x20: "SHA3",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3a: "GASPRICE",
    0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY", 0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP",
    0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST", 0x5f: "PUSH0",
    0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN", 0xf4: "DELEGATECALL", 0xf5: "CREATE2",
    0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
}
for i in range(32):
    _NAMES[0x60 + i] = f"PUSH{i + 1}"
for i in range(16):
    _NAMES[0x80 + i] = f"DUP{i + 1}"
    _NAMES[0x90 + i] = f"SWAP{i + 1}"
for i in range(5):
    _NAMES[0xa0 + i] = f"LOG{i}"

# grouped vocabulary for features: PUSHn, DUPn, SWAPn, LOGn collapse to one token each
def family(name: str) -> str:
    for p in ("PUSH", "DUP", "SWAP", "LOG"):
        if name.startswith(p) and name != "PUSH0":
            return p
    return name


VOCAB = sorted({family(n) for n in _NAMES.values()} | {"UNKNOWN"})

_META = re.compile(r"a165627a7a72305820[0-9a-f]{64}0029$|a2646970667358221220[0-9a-f]{64}64736f6c6343[0-9a-f]{6}0033$")


def _bytes(hexcode: str) -> bytes:
    h = hexcode[2:] if hexcode.startswith("0x") else hexcode
    if len(h) % 2:
        h = h[:-1]
    return bytes.fromhex(h)


def opcodes(hexcode: str) -> list[str]:
    b = _bytes(hexcode)
    out, i = [], 0
    while i < len(b):
        op = b[i]
        name = _NAMES.get(op, "UNKNOWN")
        out.append(name)
        i += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return out


def strip_metadata(hexcode: str) -> str:
    h = hexcode.lower()
    h = h[2:] if h.startswith("0x") else h
    return _META.sub("", h)


def skeleton(hexcode: str) -> str:
    return hashlib.sha1(" ".join(opcodes(strip_metadata(hexcode))).encode()).hexdigest()
