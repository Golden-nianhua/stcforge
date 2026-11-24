"""Conservative local-variable location tracking for linked SDCC listings."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
import re


SPX_REGISTER = 25
_CODE_ROW = re.compile(
    r"^ {4,}([0-9A-F]{6}) ([0-9A-F]{2}(?: [0-9A-F]{2})*)[ \t]{2,}"
    r"(?:\[\s*\d+\]\s+)?\d+\s+([a-z][a-z0-9]*)\b\s*(.*?)\s*$"
)
_SOURCE_MARK = re.compile(r"\bC\$[^$]+\$\d+\$(\d+_\d+)\$(\d+)\s*==\s*\.")
_SOURCE_TEXT = re.compile(r"^\s*\d+\s+;\s+.*:(\d+):\s+(.*)$")
_RELATIVE = {"sjmp", "jc", "jnc", "jz", "jnz", "jb", "jnb", "jbc", "cjne",
             "djnz", "je", "jne", "jg", "jge", "jl", "jle", "jsle", "jsge",
             "jsg", "jsl", "jleq", "jneq"}
_ORDINARY = {"mov", "movx", "movc", "movh", "movz", "movs", "xch", "xchd",
             "add", "addc", "sub", "subb", "cmp", "inc", "dec", "mul", "div",
             "anl", "orl", "xrl", "clr", "setb", "cpl", "rl", "rr", "rlc",
             "rrc", "swap", "da", "nop"}
_SP_DIRECT = {"sp", "sph", "spx", "dr60", "wr62", "wr60",
              "0x81", "0x85", "129", "133"}
_STACK_OPERAND = re.compile(r"@spx(?:([+-])(0x[0-9a-f]+|\d+))?")
_C_TOKENS = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    r'|(?m:^[ \t]*\#[^\n]*(?:\\\n[^\n]*)*)|[{}]', re.DOTALL
)


@dataclass(frozen=True)
class StackDecl:
    module: str
    function: str
    name: str
    scope: str
    block: str
    offset: int  # relative to SPX on entry; first local byte is +1
    size: int


@dataclass(frozen=True)
class RegisterDecl:
    module: str
    function: str
    name: str
    scope: str
    block: str
    registers: tuple[int, ...]  # CDB order: least significant byte first


@dataclass(frozen=True)
class _Instruction:
    pc: int
    data: bytes
    op: str
    args: tuple[str, ...]
    source: tuple[str, str, str] | None
    source_line: int | None

    @property
    def end(self) -> int:
        return self.pc + len(self.data)


def read_listing(path: Path) -> dict[int, _Instruction]:
    rows: dict[int, _Instruction] = {}
    marker = None
    source = None
    for text in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        mark = _SOURCE_MARK.search(text)
        if mark:
            marker = mark.groups()
            source = None
        elif marker and (comment := _SOURCE_TEXT.match(text)):
            source = (*marker, comment[2])
            source_line = int(comment[1])
        match = _CODE_ROW.match(text)
        if not match:
            continue
        addr, raw, op, operands = match.groups()
        pc = int(addr, 16)
        args = operands.partition(";")[0].strip().lower()
        row = _Instruction(pc, bytes.fromhex(raw), op,
                           tuple(arg.strip() for arg in args.split(",")) if args else (),
                           source, source_line if source is not None else None)
        if pc in rows and rows[pc] != row:
            # Overlay areas in a listing cannot establish a unique instruction.
            return {}
        rows[pc] = row
    return rows


def _effect(row: _Instruction) -> tuple[int, tuple[int, ...]] | None:
    """Return the SPX delta and successors in the current frame."""
    op, args, data, end = row.op, row.args, row.data, row.end
    if op in {"ret", "eret", "reti"}:
        return 0, ()
    if (op in _RELATIVE and args and not args[-1].startswith("@")
            and not any(arg.split(".", 1)[0] in _SP_DIRECT for arg in args[:-1])):
        target = end + int.from_bytes(data[-1:], signed=True)
        return 0, ((target,) if op == "sjmp" else (end, target))
    if op == "ejmp" and data[:1] == b"\x8a" and len(data) == 4:
        return 0, (int.from_bytes(data[1:]),)
    if op == "ljmp" and data[:1] == b"\x02" and len(data) == 3:
        return 0, ((row.pc & 0xFF0000) | int.from_bytes(data[1:]),)
    if op in {"ecall", "lcall"} and data[:1] == (b"\x9a" if op == "ecall" else b"\x12"):
        # In the current frame the instruction after a returning call sees the
        # same SPX. The callee's PC is never assigned a location for this frame.
        return 0, (end,)
    if op in {"push", "pop"}:
        if len(args) != 1 or args[0] in _SP_DIRECT:
            return None
        if len(data) == 2 and data[0] == (0xC0 if op == "push" else 0xD0):
            if op == "pop" and data[1] in {0x81, 0x85}:
                return None
            return (1 if op == "push" else -1), (end,)
        if (len(data) == 2 and data[0] == (0xCA if op == "push" else 0xDA)
                and data[1] & 0x0F == 8 and re.fullmatch(r"r(?:[0-9]|1[0-5])", args[0])):
            return (1 if op == "push" else -1), (end,)
        return None
    if op in {"inc", "dec"} and args and args[0] == "spx":
        if len(data) == 2 and data[0] == (0x0B if op == "inc" else 0x1B):
            count = {0xFC: 1, 0xFD: 2, 0xFE: 4}.get(data[1])
            if count is not None:
                return (count if op == "inc" else -count), (end,)
        return None
    if op in _ORDINARY and not any(arg in _SP_DIRECT for arg in args):
        return 0, (end,)
    return None


def _stack_store(row: _Instruction, depth: int) -> int | None:
    # Match only the byte stores that SDCC emits for initializing scalar locals.
    if row.op != "mov" or len(row.args) != 2:
        return None
    operand, value = row.args
    match = _STACK_OPERAND.fullmatch(operand)
    if not match or not re.fullmatch(r"a|r(?:[0-9]|1[0-5])|#(?:0x[0-9a-f]+|\d+)", value):
        return None
    distance = int(match[2], 0) if match[2] else 0
    return depth + (-distance if match[1] == "-" else distance)


def _verified_instructions(entry: int, end: int, rows: dict[int, _Instruction],
                           memory: dict[int, int]) -> dict[int, _Instruction]:
    # Require a complete byte-for-byte match, including dead instructions.
    pc = entry
    instructions = {}
    while pc < end:
        row = rows.get(pc)
        if (row is None or row.end > end
                or any(memory.get(pc + i) != byte for i, byte in enumerate(row.data))):
            return {}
        instructions[pc] = row
        pc = row.end
    return instructions


def stack_ranges(decl: StackDecl, entry: int, end: int,
                 rows: dict[int, _Instruction], memory: dict[int, int]
                 ) -> tuple[tuple[int, int, int], ...]:
    """Return (start PC, end PC, signed offset from live SPX) tuples."""
    instructions = _verified_instructions(entry, end, rows, memory)

    # This first version deliberately handles only initialized function-body
    # variables with dedicated, positive SPX slots, not parameters or spills.
    def in_initializer(row: _Instruction) -> bool:
        return (row.source is not None and row.source[:2] == (decl.scope, decl.block)
                and re.search(rf"\b{re.escape(decl.name)}\s*=(?!=)", row.source[2]) is not None)

    init_rows = {pc for pc, row in instructions.items() if in_initializer(row)}
    if not init_rows:
        return ()
    first_init = min(init_rows)
    # Require the usual fixed allocation at entry. This rules out storage in
    # arguments or transient pushes even when those bytes are later written.
    frame = 0
    pc = entry
    while pc in instructions and instructions[pc].args[:1] == ("spx",):
        row = instructions[pc]
        effect = _effect(row)
        if row.op != "inc" or effect is None or effect[0] <= 0:
            break
        frame += effect[0]
        pc = row.end
    slot_end = decl.offset + decl.size - 1
    if not 1 <= decl.offset <= slot_end <= frame:
        return ()

    # Join only identical depths. A variable byte is available at a join only
    # when every incoming path has initialized it.
    pending = deque([entry])
    states = {entry: (0, 0)}
    all_written = (1 << decl.size) - 1
    while pending:
        pc = pending.popleft()
        depth, written = states[pc]
        row = instructions[pc]
        effect = _effect(row)
        if effect is None:
            return ()
        delta, successors = effect
        if pc == first_init:
            written = 0
        if depth + delta < slot_end:
            written = 0
        if pc in init_rows and depth >= slot_end:
            byte_offset = _stack_store(row, depth)
            if byte_offset is not None and decl.offset <= byte_offset <= slot_end:
                written |= 1 << (byte_offset - decl.offset)
        next_depth = depth + delta
        if not 0 <= next_depth <= 0x3FFF:
            return ()
        for successor in successors:
            if successor not in instructions:
                return ()
            previous = states.get(successor)
            if previous is not None and previous[0] != next_depth:
                return ()
            state = (next_depth, written if previous is None else previous[1] & written)
            if state != previous:
                states[successor] = state
                pending.append(successor)

    ranges: list[tuple[int, int, int]] = []
    for pc, (depth, written) in sorted(states.items()):
        if pc <= first_init or depth < slot_end or written != all_written:
            continue
        offset = decl.offset - depth
        end_pc = instructions[pc].end
        if ranges and ranges[-1][1:] == (pc, offset):
            ranges[-1] = ranges[-1][0], end_pc, offset
        else:
            ranges.append((pc, end_pc, offset))
    return tuple(ranges)


def _reg_bytes(operand: str) -> frozenset[int]:
    match = re.fullmatch(r"(r|wr|dr|ar)(\d+)(?:\.[0-7])?", operand)
    if match:
        width = {"r": 1, "wr": 2, "dr": 4, "ar": 1}[match[1]]
        first = int(match[2])
        return frozenset(range(first, min(first + width, 16)))
    if re.fullmatch(r"0x[0-9a-f]+|[0-9]+", operand):
        address = int(operand, 16 if operand.startswith("0x") else 10)
        if address < 0x20:
            return frozenset([address & 7])
    return frozenset()


def _writes(row: _Instruction) -> frozenset[int]:
    op = row.op
    if not row.args or op in {"cmp", "cjne", "push"}:
        return frozenset()
    if op in {"mul", "div"}:
        return frozenset(range(16))  # Some forms write a wider result.
    if op in _ORDINARY or op in {"pop", "djnz", "jbc"}:
        targets = row.args[:2] if op in {"xch", "xchd"} else row.args[:1]
        if any(arg.split(".", 1)[0] in {"psw", "psw1", "0xd0", "0xd1", "208", "209"}
               for arg in targets):
            return frozenset(range(8))  # A bank selection may change R0..R7.
        return frozenset().union(*map(_reg_bytes, targets))
    return frozenset()


def _call_target(row: _Instruction) -> int | None:
    if row.op == "ecall" and len(row.data) == 4 and row.data[0] == 0x9A:
        return int.from_bytes(row.data[1:])
    if row.op == "lcall" and len(row.data) == 3 and row.data[0] == 0x12:
        return (row.pc & 0xFF0000) | int.from_bytes(row.data[1:])
    return None


def call_clobbers(rows: dict[int, _Instruction], memory: dict[int, int],
                  functions: dict[int, int]) -> Callable[[int], frozenset[int]]:
    """Return a memoized, conservative summary of writes by linked callees."""
    all_registers = frozenset(range(16))
    active: set[int] = set()

    @cache
    def clobbers(entry: int) -> frozenset[int]:
        if entry in active or entry not in functions or len(active) >= 32:
            return all_registers
        end = functions[entry]
        if end == entry:
            # Linker-only assembly symbol: accept only a bounded NOP/return stub.
            cursor = entry
            for _ in range(16):
                row = rows.get(cursor)
                if row is None or row.data not in {b"\x00", b"\x22", b"\xaa"}:
                    return all_registers
                cursor = row.end
                if row.data != b"\x00":
                    end = cursor
                    break
        instructions = _verified_instructions(entry, end, rows, memory)
        if not instructions:
            return all_registers
        active.add(entry)
        try:
            written = set()
            pending = [entry]
            visited = set()
            while pending:
                pc = pending.pop()
                if pc in visited:
                    continue
                visited.add(pc)
                row = instructions.get(pc)
                if row is None or (effect := _effect(row)) is None:
                    return all_registers
                if row.op in {"ecall", "lcall"}:
                    target = _call_target(row)
                    if target is None:
                        return all_registers
                    written.update(clobbers(target))
                else:
                    written.update(_writes(row))
                    # Indirect writes may alias the low register banks.
                    if row.args and row.args[0].startswith("@") and row.op in _ORDINARY:
                        written.update(range(8))
                pending.extend(effect[1])
            return frozenset(written)
        finally:
            active.remove(entry)

    return clobbers


def _scope_end(text: str, line: int, initializer: str) -> int | None:
    """Find the closing brace of the compound containing the declaration."""
    lines = text.splitlines(keepends=True)
    if (not 1 <= line <= len(lines) or lines[line - 1].strip() != initializer.strip()):
        return None
    offset = sum(map(len, lines[:line - 1]))
    open_blocks = []
    for token in _C_TOKENS.finditer(text):
        if token.start() >= offset:
            if not open_blocks:
                return None
            block = open_blocks[-1]
            break
        if token[0] == "{":
            open_blocks.append(token.start())
        elif token[0] == "}":
            if not open_blocks:
                return None
            open_blocks.pop()
    else:
        return None
    depth = 0
    for token in _C_TOKENS.finditer(text, block):
        if re.match(r"\s*#\s*(?:if|ifdef|ifndef|else|elif|endif)\b", token[0]):
            return None  # Source alternatives may have different block extents.
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if not depth:
                return text.count("\n", 0, token.start()) + 1
    return None


@dataclass(frozen=True)
class RegisterPiece:
    register: int
    spx_offset: int | None = None


def _assignment_sites(decl: RegisterDecl, instructions: dict[int, _Instruction],
                      declaration: re.Pattern[str], source: str,
                      source_bounds: tuple[int, int] | None
                      ) -> tuple[list[list[int]], int, int] | None:
    """Recover direct call assignments when the declaration emitted no code."""
    lines = source.splitlines()
    emitted_lines = {row.source_line for row in instructions.values()
                     if row.source_line is not None}
    if not emitted_lines:
        return None
    # The CDB includes line records for the signature and for some elided
    # statements, even when the linked listing tags no instruction with them.
    first_line, last_line = source_bounds or (min(emitted_lines), max(emitted_lines))
    occurrences = [(n, text) for n, text in enumerate(lines, 1)
                   if first_line <= n <= last_line and declaration.match(text)]
    # A bare assignment does not carry the declaration's CDB scope ID.
    if len(occurrences) != 1:
        return None
    start, text = occurrences[0]
    if start in emitted_lines:
        return None
    end = _scope_end(source, start, text)
    if end is None:
        return None
    assignment = re.compile(
        rf"^\s*{re.escape(decl.name)}\s*=\s*([A-Za-z_]\w*)\s*\([^();]*\)\s*;\s*$")
    grouped: dict[int, list[_Instruction]] = {}
    for row in instructions.values():
        if row.source and row.source_line is not None and start < row.source_line < end:
            grouped.setdefault(row.source_line, []).append(row)
    sites = []
    return_bytes = dict(zip(decl.registers, ("dpl", "dph", "b", "a")))
    for line, rows in grouped.items():
        match = assignment.fullmatch(lines[line - 1])
        if not match or any(row.source[2].strip() != lines[line - 1].strip() for row in rows):
            continue
        if any(a.end != b.pc for a, b in zip(rows, rows[1:])):
            continue
        calls = [i for i, row in enumerate(rows) if _call_target(row) is not None]
        if len(calls) != 1 or rows[calls[0]].args != ("_" + match[1].lower(),):
            continue
        # Only count exact copies of the SDCC scalar return bytes, not scratch
        # writes earlier in the source statement.
        copies = rows[calls[0] + 1:calls[0] + 1 + len(decl.registers)]
        expected = {(f"r{reg}", origin) for reg, origin in return_bytes.items()}
        if (len(copies) != len(expected) or any(row.op != "mov" for row in copies)
                or {row.args for row in copies} != expected):
            continue
        sites.append([row.pc for row in copies])
    return (sites, start, end) if sites else None


def register_ranges(decl: RegisterDecl, entry: int, end: int,
                    rows: dict[int, _Instruction], memory: dict[int, int],
                    source_text: str | None, clobbers: Callable[[int], frozenset[int]],
                    source_bounds: tuple[int, int] | None = None
                    ) -> tuple[tuple[int, int, tuple[RegisterPiece, ...]], ...]:
    """Track value bytes in home registers and verified caller-save slots."""
    instructions = _verified_instructions(entry, end, rows, memory)
    home = frozenset(decl.registers)
    # Match a declaration with a simple initializer, not an arbitrary write.
    decl_prefix = rf"^\s*(?:[A-Za-z_]\w*[ \t]+)+{re.escape(decl.name)}\s*"
    declaration = re.compile(decl_prefix + r"=(?!=)")
    initializers = [pc for pc, row in instructions.items()
                    if row.source is not None and row.source[:2] == (decl.scope, decl.block)
                    and declaration.match(row.source[2])]
    if initializers:
        start = initializers[0]
        init_line = instructions[start].source_line
        if initializers != [pc for pc in instructions if start <= pc <= initializers[-1]]:
            return ()  # Do not infer split initializer blocks.
        sites = [initializers]
        scope_end = (_scope_end(source_text, init_line, instructions[start].source[2])
                     if source_text is not None else None)
    else:
        bare_declaration = re.compile(decl_prefix + r"(?:=(?!=)|;\s*$)")
        recovered = (_assignment_sites(decl, instructions, bare_declaration, source_text,
                                       source_bounds)
                     if source_text is not None else None)
        if recovered is None:
            return ()
        sites, init_line, scope_end = recovered
    starts = {site[0] for site in sites}
    init_set = set().union(*sites)
    finishes = {instructions[site[-1]].end for site in sites}
    finish = min(finishes)

    # State is control-flow stack depth, known home registers, and known saved
    # copies (entry-relative EDATA offset -> home register). At joins retain
    # only facts common to every predecessor.
    pending = deque([entry])
    states = {entry: (0, frozenset(), frozenset())}
    while pending:
        pc = pending.popleft()
        depth, live, saved_items = states[pc]
        row = instructions[pc]
        effect = _effect(row)
        if effect is None:
            return ()
        delta, successors = effect
        if pc in starts:
            live, saved_items = frozenset(), frozenset()
        if pc in init_set and successors != (row.end,):
            return ()
        saved = dict(saved_items)
        changed = _writes(row)
        next_live = live - changed
        if row.op in {"ecall", "lcall"}:
            target = _call_target(row)
            next_live = next_live - (clobbers(target) if target is not None else home)
        if row.op == "push" and delta == 1:
            register = _reg_bytes(row.args[0]) & next_live
            saved.pop(depth + 1, None)
            if len(register) == 1:
                saved[depth + 1] = next(iter(register))
        elif row.op == "pop" and delta == -1:
            register = saved.get(depth)
            if register is not None and _reg_bytes(row.args[0]) == {register}:
                next_live |= {register}
        elif row.args and row.args[0].startswith("@spx") and row.op in _ORDINARY:
            # A store can invalidate a saved value; do not assume its width.
            saved.clear()
        if (pc in init_set and row.op == "mov" and len(changed) == 1
                and re.fullmatch(r"r(?:[0-9]|1[0-5])", row.args[0])):
            next_live |= home & changed
        next_depth = depth + delta
        if not 0 <= next_depth <= 0x3FFF:
            return ()
        next_saved = frozenset((slot, reg) for slot, reg in saved.items() if slot <= next_depth)
        for successor in successors:
            if successor not in instructions or (successor in init_set and successor not in starts
                                                  and pc not in init_set):
                return ()
            previous = states.get(successor)
            if previous and previous[0] != next_depth:
                return ()
            state = (next_depth, next_live if previous is None else previous[1] & next_live,
                     next_saved if previous is None else previous[2] & next_saved)
            if state != previous:
                states[successor] = state
                pending.append(successor)

    if not any(pc in states and states[pc][1] == home for pc in finishes):
        return ()
    if scope_end is None:
        # Without a matching source block, retain the conservative listing bound.
        name_use = re.compile(rf"\b{re.escape(decl.name)}\b")
        use_lines = {row.source_line for pc, row in instructions.items()
                     if pc >= finish and row.source is not None and row.source_line > init_line
                     and pc in states and name_use.search(row.source[2])
                     and any(_reg_bytes(arg) & home for arg in row.args)}
        if not use_lines:
            return ()
        scope_end = max(use_lines) + 1

    ranges: list[tuple[int, int, tuple[RegisterPiece, ...]]] = []
    for pc, (depth, live, saved) in sorted(states.items()):
        row = instructions[pc]
        if ((initializers and pc < finish) or pc in init_set or row.source_line is None
                or not init_line < row.source_line < scope_end):
            continue
        slots = {reg: slot for slot, reg in sorted(saved)}
        if not home <= live | slots.keys():
            continue
        pieces = tuple(RegisterPiece(reg, None if reg in live else slots[reg] - depth)
                       for reg in reversed(decl.registers))
        if ranges and ranges[-1][1:] == (pc, pieces):
            ranges[-1] = ranges[-1][0], row.end, pieces
        else:
            ranges.append((pc, row.end, pieces))
    return tuple(ranges)
