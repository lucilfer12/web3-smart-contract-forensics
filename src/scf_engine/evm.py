from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x10: "LT", 0x11: "GT",
    0x14: "EQ", 0x15: "ISZERO", 0x20: "SHA3", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x39: "CODECOPY", 0x3b: "EXTCODESIZE", 0x3f: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP",
    0x57: "JUMPI", 0x5b: "JUMPDEST", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf4: "DELEGATECALL",
    0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
}


@dataclass(frozen=True)
class Instruction:
    pc: int
    opcode: int
    mnemonic: str
    operand: str | None = None


def decode_bytecode(value: str) -> bytes:
    raw = value.strip().removeprefix("0x")
    if len(raw) % 2:
        raise ValueError("bytecode must contain an even number of hex characters")
    return bytes.fromhex(raw)


def disassemble(value: str) -> list[Instruction]:
    code = decode_bytecode(value)
    result: list[Instruction] = []
    pc = 0
    while pc < len(code):
        opcode = code[pc]
        mnemonic = OPCODES.get(opcode, f"OP_{opcode:02X}")
        operand = None
        size = 1
        if 0x60 <= opcode <= 0x7f:
            width = opcode - 0x5f
            operand_bytes = code[pc + 1:pc + 1 + width]
            operand = "0x" + operand_bytes.hex()
            mnemonic = f"PUSH{width}"
            size += width
        result.append(Instruction(pc, opcode, mnemonic, operand))
        pc += size
    return result


def analyze_bytecode(value: str) -> dict[str, Any]:
    instructions = disassemble(value)
    counts: dict[str, int] = {}
    for item in instructions:
        counts[item.mnemonic] = counts.get(item.mnemonic, 0) + 1
    pushes = [item.operand for item in instructions if item.mnemonic == "PUSH4" and item.operand]
    push_constants = [item.operand for item in instructions if item.operand]
    eip1967_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    proxy = any(eip1967_slot.lower() in (item or "").lower() for item in push_constants)
    return {
        "instruction_count": len(instructions),
        "opcode_counts": counts,
        "call_like": sum(counts.get(name, 0) for name in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL")),
        "storage_reads": counts.get("SLOAD", 0),
        "storage_writes": counts.get("SSTORE", 0),
        "delegatecalls": counts.get("DELEGATECALL", 0),
        "selfdestructs": counts.get("SELFDESTRUCT", 0),
        "timestamp_reads": counts.get("TIMESTAMP", 0),
        "blockhash_reads": counts.get("BLOCKHASH", 0),
        "candidate_selectors": pushes,
        "possible_eip1967_proxy": proxy,
        "bytecode_size": len(decode_bytecode(value)),
        "heuristic_notes": ["EIP-1967 slot detection is byte-pattern evidence, not a proof of proxy semantics."],
        "instructions": [asdict(item) for item in instructions],
    }
