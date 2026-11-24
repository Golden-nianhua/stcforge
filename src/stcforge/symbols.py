"""Convert SDCC CDB and Intel HEX into a minimal MCS-251 debug ELF.

The output is deliberately an ELF32 big-endian file with ``EM_NONE``.  A GDB
port for MCS-251 must select its architecture explicitly; this converter does
not pretend that the image is ARM, x86, or any other existing ELF machine.

Provides source lines, typed globals and verified local locations.
Unsupported CDB records are counted rather than assigned guessed addresses.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cdb_types import CdbType, TypeTable
from .stack_symbols import (
    SPX_REGISTER, RegisterDecl, StackDecl, call_clobbers, read_listing, register_ranges,
    stack_ranges,
)


SFR_BASE = 0x10000000
EDATA_END = 0x4000
XDATA_START = 0x010000
XDATA_END = 0x02FFFF
CODE_START_MCS251 = 0xFC2800
CODE_END = 0xFFFFFF
MAX_TEXT_SPAN = 16 * 1024 * 1024


class SymbolConversionError(ValueError):
    """Raised when CDB or HEX input cannot be converted without guessing."""


@dataclass(frozen=True)
class _VarDecl:
    name: str
    module: str | None
    scope: str
    type: CdbType
    storage: str


@dataclass(frozen=True)
class _Function:
    name: str
    module: str | None
    scope: str
    address: int
    size: int


@dataclass(frozen=True)
class _Variable:
    name: str
    module: str | None
    scope: str
    address: int
    type: CdbType
    storage: str


@dataclass(frozen=True)
class _Local:
    decl: StackDecl | RegisterDecl
    type: CdbType
    locations: tuple[tuple[int, int, bytes], ...]


@dataclass(frozen=True)
class _Line:
    file: str
    line: int
    address: int


@dataclass
class _ParsedCdb:
    function_decls: dict[tuple[str, str | None, str], str]
    function_prototypes: set[str]
    variable_decls: dict[tuple[str, str | None, str], _VarDecl]
    starts: dict[tuple[str, str | None, str], int]
    ends: dict[tuple[str, str | None, str], int]
    lines: list[_Line]
    counters: dict[str, int]
    samples: dict[str, list[str]]
    stack_decls: dict[StackDecl, CdbType]
    register_decls: dict[RegisterDecl, CdbType]
    local_scopes: dict[tuple[str, str, str], set[tuple[str, str]]]
    types: TypeTable


@dataclass(frozen=True)
class _ElfSymbol:
    name: str
    value: int
    size: int
    bind: int
    kind: int
    shndx: int


def _uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 cannot encode a negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign = byte & 0x40
        if (value == 0 and not sign) or (value == -1 and sign):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def _cstring(text: str) -> bytes:
    return text.encode("utf-8") + b"\x00"


def _static_name(scope: str, rest: str) -> tuple[str | None, str]:
    """Extract a variable name while allowing '$' inside the module name."""
    if scope == "G":
        if not rest.startswith("$"):
            raise SymbolConversionError("invalid global variable name")
        return None, rest[1:].split("$", 1)[0]
    if not rest or "$" not in rest:
        raise SymbolConversionError("invalid file-static variable name")
    module, body = rest.split("$", 1)
    name = body.split("$", 1)[0]
    if not module or not name:
        raise SymbolConversionError("invalid file-static variable name")
    return module, name


def _function_key(scope: str, rest: str) -> tuple[str, str | None, str]:
    """Extract the linker symbol from F:G$name$... or F:Ffile$name$..."""
    if scope == "G":
        if not rest.startswith("$"):
            raise SymbolConversionError("invalid global function name")
        return ("G", None, rest[1:].split("$", 1)[0])
    if "$" not in rest:
        raise SymbolConversionError("invalid file-static function name")
    module, body = rest.split("$", 1)
    name = body.split("$", 1)[0]
    if not module or not name:
        raise SymbolConversionError("invalid file-static function name")
    return ("F", module, name)


def _line_record_key(tag: str, rest: str) -> tuple[str, str | None, str]:
    """Return the declaration key corresponding to an L:G/L:XG/L:F/L:XF."""
    if tag in {"G", "XG"}:
        name = rest.split("$", 1)[0]
        if not name:
            raise SymbolConversionError("empty global address symbol")
        return "G", None, name
    if tag in {"F", "XF"}:
        if "$" not in rest:
            raise SymbolConversionError("invalid static address symbol")
        module, body = rest.split("$", 1)
        # F address names are module$variable$allocation_suffix.  The address
        # suffix starts with a decimal slot number after the variable.
        match = re.match(r"(.+?)\$\d", body)
        name = match.group(1) if match else body
        if not module or not name:
            raise SymbolConversionError("empty static address symbol")
        return "F", module, name
    raise SymbolConversionError("invalid address record tag")


def _sample(samples: dict[str, list[str]], key: str, value: str) -> None:
    bucket = samples.setdefault(key, [])
    if value not in bucket and len(bucket) < 5:
        bucket.append(value)


def _bump(counters: dict[str, int], samples: dict[str, list[str]], key: str,
          value: str | None = None) -> None:
    counters[key] = counters.get(key, 0) + 1
    if value is not None:
        _sample(samples, key, value)


def _remember_raw(target: dict[tuple[str, str | None, str], int],
                  key: tuple[str, str | None, str], value: int,
                  counters: dict[str, int]) -> None:
    old = target.get(key)
    if old is None:
        target[key] = value
    elif old != value:
        raise SymbolConversionError(
            f"CDB symbol {key[2]!r} has conflicting addresses "
            f"0x{old:X} and 0x{value:X}"
        )
    else:
        counters["duplicate_address_records"] = (
            counters.get("duplicate_address_records", 0) + 1
        )


def _parse_cdb(path: Path) -> _ParsedCdb:
    function_decls: dict[tuple[str, str | None, str], str] = {}
    function_prototypes: set[str] = set()
    variable_decls: dict[tuple[str, str | None, str], _VarDecl] = {}
    starts: dict[tuple[str, str | None, str], int] = {}
    ends: dict[tuple[str, str | None, str], int] = {}
    lines: list[_Line] = []
    line_set: set[_Line] = set()
    stack_decls = {}
    register_decls = {}
    local_scopes: dict[tuple[str, str, str], set[tuple[str, str]]] = {}
    counters: dict[str, int] = {
        "locals": 0,
        "unknown_types": 0,
        "bit_variables": 0,
        "unsupported_storage": 0,
        "macros": 0,
        "missing_variable_address": 0,
        "missing_function_address": 0,
        "malformed_records": 0,
        "duplicate_declarations": 0,
        "duplicate_lines": 0,
        "duplicate_address_records": 0,
    }
    samples: dict[str, list[str]] = {}

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    types = TypeTable(text)
    current_module = ""
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("M:"):
            current_module = line[2:]
            continue

        if line.startswith("S:C"):
            _bump(counters, samples, "macros", line)
            continue

        if line.startswith("F:"):
            match = re.match(r"^F:([GF])(.*?)\((\{[^}]*\}[^)]*)\)", line)
            if not match:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            scope, rest, type_text = match.groups()
            try:
                key = _function_key(scope, rest)
            except SymbolConversionError:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            if key in function_decls:
                if function_decls[key] != type_text:
                    raise SymbolConversionError(
                        f"CDB function {key[2]!r} has conflicting declarations"
                    )
                counters["duplicate_declarations"] += 1
            else:
                function_decls[key] = type_text
            continue

        if line.startswith("L:"):
            if line.startswith("L:A"):
                counters["assembly_records"] = counters.get("assembly_records", 0) + 1
                continue
            if line.startswith("L:L"):
                _bump(counters, samples, "local_address_records", line)
                continue
            colon = line.rfind(":")
            if colon <= 2:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            head, address_text = line[:colon], line[colon + 1:]
            if not re.fullmatch(r"[0-9A-Fa-f]+", address_text):
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            # CDB uses "L:G$...", "L:XG$...", "L:C$..." but "L:Fmodule$..."
            # and "L:XFmodule$..." (no separator after the tag).  Parse known
            # prefixes explicitly instead of relying on a greedy tag regex.
            tag = ""
            rest = ""
            for prefix in ("XF", "XG", "G", "F", "C"):
                if head.startswith("L:" + prefix):
                    after = head[2 + len(prefix):]
                    if prefix in {"G", "XG", "C"} and after.startswith("$"):
                        tag, rest = prefix, after[1:]
                        break
                    if prefix in {"F", "XF"} and after and not after.startswith("$"):
                        tag, rest = prefix, after
                        break
            if not tag:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            raw_address = int(address_text, 16)
            if tag == "C":
                parts = rest.split("$")
                if len(parts) < 2 or not parts[1].isdigit():
                    _bump(counters, samples, "malformed_records",
                          f"line {number}: {line}")
                    continue
                entry = _Line(parts[0].replace("\\", "/"), int(parts[1]), raw_address)
                if entry in line_set:
                    counters["duplicate_lines"] += 1
                else:
                    line_set.add(entry)
                    lines.append(entry)
            elif tag in {"G", "XG", "F", "XF"}:
                try:
                    key = _line_record_key(tag, rest)
                except SymbolConversionError:
                    _bump(counters, samples, "malformed_records",
                          f"line {number}: {line}")
                    continue
                target = starts if tag in {"G", "F"} else ends
                _remember_raw(target, key, raw_address, counters)
            continue

        if line.startswith("S:"):
            match = re.match(r"^S:([GFL])([^()]*)\((\{[^}]*\}[^)]*)\),(.*)$", line)
            if not match:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            scope, rest, type_text, tail = match.groups()
            fields = [field.strip() for field in tail.split(",")]
            storage = fields[0] if fields else ""
            if scope == "L":
                name = re.fullmatch(r"(.+)\.([^.$]+)\$([^$]+)\$(\d+_\d+)\$(\d+)", rest)
                if name:
                    module, function, identifier, level, block = name.groups()
                    local_scopes.setdefault((module, function, identifier), set()).add((level, block))
                type_ = types.parse(type_text, name[1] if name else current_module)
                registers = re.fullmatch(r"R,0,0,\[(r\d+(?:,r\d+)*)\]", tail)
                if (name and type_ and name[4].startswith("1_")
                        and len(fields) == 3 and fields[:2] == ["B", "1"]
                        and re.fullmatch(r"[1-9]\d*", fields[2])):
                    stack = StackDecl(*name.groups(), int(fields[2]), type_.size)
                    stack_decls[stack] = type_
                    continue
                if name and type_ and registers:
                    order = tuple(int(reg[1:]) for reg in registers[1].split(","))
                    if len(order) == len(set(order)) == type_.size and all(r < 16 for r in order):
                        register_decls[RegisterDecl(*name.groups(), order)] = type_
                        continue
                _bump(counters, samples, "locals", f"{rest}:{type_text}")
                continue
            if scope not in {"G", "F"}:
                continue
            try:
                module, name = _static_name(scope, rest)
            except SymbolConversionError:
                _bump(counters, samples, "malformed_records", f"line {number}: {line}")
                continue
            if re.match(r"^\{\d+\}DF,", type_text) or storage == "C":
                if scope == "G" and storage == "C" and re.match(r"^\{\d+\}DF,", type_text):
                    function_prototypes.add(name)
                continue
            if re.search(r"(?:\}|,)SX(?::[SU])?$", type_text) or storage == "J":
                _bump(counters, samples, "bit_variables", name)
                continue
            type_ = types.parse(type_text, module or current_module)
            if type_ is None:
                _bump(counters, samples, "unknown_types", f"{name}:{type_text}")
                continue
            if storage not in {"I", "E", "F", "D"}:
                _bump(counters, samples, "unsupported_storage", f"{name}:{storage}")
                continue
            key = (scope, module, name)
            decl = _VarDecl(name, module, scope, type_, storage)
            old = variable_decls.get(key)
            if old is None:
                variable_decls[key] = decl
            elif old == decl:
                counters["duplicate_declarations"] += 1
            else:
                raise SymbolConversionError(
                    f"CDB symbol {name!r} has conflicting declarations"
                )
            continue

        # M: module records, A: address records and unknown records do not
        # contribute to this minimal converter.

    # Address records contain the module-qualified spelling, while S:F
    # declarations only carry the module.  Match F addresses to declarations
    # by (module, variable name) only when that pair is unique; ambiguity is
    # an error rather than an invitation to choose one at random.
    static_decls: dict[tuple[str, str], tuple[str, str | None, str]] = {}
    ambiguous: set[tuple[str, str]] = set()
    for key, decl in variable_decls.items():
        if decl.scope != "F" or decl.module is None:
            continue
        pair = (decl.module, decl.name)
        if pair in static_decls:
            ambiguous.add(pair)
        static_decls[pair] = key
    normalized_starts: dict[tuple[str, str | None, str], int] = {}
    for key, address in starts.items():
        scope, module, name = key
        if scope == "F" and module is not None:
            pair = (module, name)
            if pair in ambiguous:
                raise SymbolConversionError(
                    f"file-static symbol {module}${name} is ambiguous"
                )
            declaration_key = static_decls.get(pair)
            if declaration_key is not None:
                key = declaration_key
        _remember_raw(normalized_starts, key, address, counters)

    overlap = set(function_decls).intersection(variable_decls)
    if overlap:
        scope, module, name = sorted(overlap)[0]
        raise SymbolConversionError(
            f"CDB symbol {module or ''}${name} is both a function and a variable"
        )

    return _ParsedCdb(function_decls, function_prototypes, variable_decls, normalized_starts, ends,
                      lines, counters, samples, stack_decls, register_decls, local_scopes, types)


def read_hex(path: Path) -> dict[int, int]:
    """Read Intel HEX with strict checksum, overlap, extension, and EOF checks."""
    memory: dict[int, int] = {}
    base = 0
    ended = False
    for number, raw_line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if ended:
            raise SymbolConversionError(
                f"HEX line {number}: duplicate EOF record or data after EOF"
            )
        if not line.startswith(":"):
            raise SymbolConversionError(f"HEX line {number}: missing ':'")
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as error:
            raise SymbolConversionError(f"HEX line {number}: invalid hex digits") from error
        if len(record) < 5:
            raise SymbolConversionError(f"HEX line {number}: record too short")
        count = record[0]
        if len(record) != count + 5:
            raise SymbolConversionError(f"HEX line {number}: length mismatch")
        if sum(record) & 0xFF:
            raise SymbolConversionError(f"HEX line {number}: checksum mismatch")
        offset = (record[1] << 8) | record[2]
        kind = record[3]
        data = record[4:-1]

        if kind == 0x00:
            if offset + count > 0x10000:
                raise SymbolConversionError(
                    f"HEX line {number}: data record crosses the 16-bit offset boundary"
                )
            address = base + offset
            if address + count > CODE_END + 1:
                raise SymbolConversionError(
                    f"HEX line {number}: address exceeds the 24-bit MCS-251 space"
                )
            for index, value in enumerate(data):
                current = address + index
                if current in memory:
                    raise SymbolConversionError(
                        f"HEX line {number}: overlapping address 0x{current:06X}"
                    )
                memory[current] = value
        elif kind == 0x01:
            if count != 0 or offset != 0:
                raise SymbolConversionError(f"HEX line {number}: malformed EOF record")
            ended = True
        elif kind == 0x02:
            if count != 2 or offset != 0:
                raise SymbolConversionError(
                    f"HEX line {number}: malformed extended segment address"
                )
            base = int.from_bytes(data, "big") << 4
        elif kind == 0x04:
            if count != 2 or offset != 0:
                raise SymbolConversionError(
                    f"HEX line {number}: malformed extended linear address"
                )
            base = int.from_bytes(data, "big") << 16
        elif kind in {0x03, 0x05}:
            if count != 4 or offset != 0:
                raise SymbolConversionError(
                    f"HEX line {number}: malformed start address record"
                )
            # Start records are not program bytes and are intentionally ignored.
        else:
            raise SymbolConversionError(
                f"HEX line {number}: unsupported record type 0x{kind:02X}"
            )

    if not ended:
        raise SymbolConversionError("HEX is missing the EOF record")
    if not memory:
        raise SymbolConversionError("HEX contains no program data")
    return memory


def _is_code_address(address: int) -> bool:
    return CODE_START_MCS251 <= address <= CODE_END


def _map_code_address(raw: int) -> int:
    if not _is_code_address(raw):
        raise SymbolConversionError(f"unsupported SDCC code address 0x{raw:X}")
    return raw


def _map_storage_address(storage: str, raw: int) -> int:
    if storage == "D":
        return _map_code_address(raw)
    if storage == "I":
        if not 0x80 <= raw <= 0xFF:
            raise SymbolConversionError(f"SFR address 0x{raw:X} is outside 0x80..0xFF")
        return SFR_BASE + raw
    if storage == "E":
        if not 0 <= raw < EDATA_END:
            raise SymbolConversionError(
                f"EDATA address 0x{raw:X} is outside 0x0000..0x3FFF"
            )
        return raw
    if storage == "F":
        if not XDATA_START <= raw <= XDATA_END:
            raise SymbolConversionError(
                f"XDATA address 0x{raw:X} is outside 0x010000..0x02FFFF"
            )
        return raw
    raise SymbolConversionError(f"unsupported storage class {storage!r}")


def _build_functions(parsed: _ParsedCdb) -> list[_Function]:
    functions: list[_Function] = []
    for key, _type_text in parsed.function_decls.items():
        scope, module, name = key
        if key not in parsed.starts:
            _bump(parsed.counters, parsed.samples, "missing_function_address", name)
            continue
        address = _map_code_address(parsed.starts[key])
        size = 0
        if key in parsed.ends:
            end = _map_code_address(parsed.ends[key])
            if end < address:
                raise SymbolConversionError(
                    f"function {name!r} ends before its start address"
                )
            # SDCC's XG/XF record is the address of the final instruction
            # byte (for example the terminating ERET), not an exclusive end.
            size = end - address + 1
        functions.append(_Function(name, module, scope, address, size))
    return functions


def _map_functions(path: Path, parsed: _ParsedCdb, functions: list[_Function],
                   memory: dict[int, int]) -> list[_Function]:
    """Recover assembly function entry points declared in C, without guessing sizes."""
    wanted = parsed.function_prototypes - {func.name for func in functions}
    if not wanted or not path.is_file():
        return []
    entries: dict[str, set[int]] = {}
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        match = re.fullmatch(r"\s*C:\s+([0-9A-Fa-f]{6,8})\s+_([A-Za-z_]\w*)(?:\s+\S+)?\s*", line)
        if match and match[2] in wanted:
            entries.setdefault(match[2], set()).add(int(match[1], 16))

    recovered = []
    for name, addresses in sorted(entries.items()):
        if len(addresses) != 1:
            continue
        address = next(iter(addresses))
        if (address not in memory
                or any(func.address <= address < func.address + max(1, func.size)
                       for func in functions + recovered)):
            continue
        recovered.append(_Function(name, None, "G", address, 0))
    return recovered


def _build_variables(parsed: _ParsedCdb) -> list[_Variable]:
    variables: list[_Variable] = []
    for key, decl in parsed.variable_decls.items():
        if key not in parsed.starts:
            _bump(parsed.counters, parsed.samples, "missing_variable_address", decl.name)
            continue
        raw = parsed.starts[key]
        address = _map_storage_address(decl.storage, raw)
        variables.append(_Variable(decl.name, decl.module, decl.scope, address,
                                   decl.type, decl.storage))
    return variables


def _filter_ambiguous_file_statics(parsed: _ParsedCdb,
                                   variables: list[_Variable]) -> list[_Variable]:
    """Drop file statics whose bare name occurs in more than one module.

    The minimal ELF has one compile unit and GDB resolves variables by name.
    Keeping two ``same`` variables from different modules would therefore be
    ambiguous even though their addresses are correct.  A future multi-CU
    implementation can preserve both; for now they are skipped explicitly.
    """
    by_name: dict[str, list[_Variable]] = {}
    for variable in variables:
        by_name.setdefault(variable.name, []).append(variable)
    # 同名全局变量/函数也会覆盖静态变量的裸名查找，不能只比较静态变量。
    ambiguous = ({name for name, items in by_name.items() if len(items) > 1}
                 | {key[2] for key in parsed.function_decls})
    kept: list[_Variable] = []
    for variable in variables:
        if variable.scope == "F" and variable.name in ambiguous:
            _bump(parsed.counters, parsed.samples, "ambiguous_file_statics",
                  f"{variable.module}${variable.name}")
        else:
            kept.append(variable)
    # Keep the zero explicit in the summary so callers can render every
    # supported counter without special-casing absent keys.
    parsed.counters.setdefault("ambiguous_file_statics", 0)
    return kept


def _check_global_collisions(functions: list[_Function],
                             variables: list[_Variable]) -> None:
    global_functions: dict[str, int] = {}
    for function in functions:
        if function.scope != "G":
            continue
        old = global_functions.get(function.name)
        if old is not None and old != function.address:
            raise SymbolConversionError(
                f"global function {function.name!r} has conflicting addresses"
            )
        global_functions[function.name] = function.address
    for variable in variables:
        if variable.scope != "G":
            continue
        if variable.name in global_functions:
            raise SymbolConversionError(
                f"global symbol {variable.name!r} is both a function and a variable"
            )


def _make_text(memory: dict[int, int]) -> tuple[int, int, bytes, int]:
    outside = sorted(address for address in memory if not _is_code_address(address))
    if outside:
        first = outside[0]
        raise SymbolConversionError(
            f"HEX address 0x{first:06X} is outside the supported MCS-251 code "
            f"range 0x{CODE_START_MCS251:06X}..0x{CODE_END:06X}; "
            "low Keil addresses are not offset automatically"
        )
    code_addresses = sorted(address for address in memory if _is_code_address(address))
    if not code_addresses:
        raise SymbolConversionError("HEX has no bytes in an SDCC code address range")
    start = code_addresses[0]
    end = code_addresses[-1]
    span = end - start + 1
    if span > MAX_TEXT_SPAN:
        raise SymbolConversionError(
            f"code span 0x{start:X}..0x{end:X} is larger than 16 MiB"
        )
    text = bytearray(b"\xFF" * span)
    for address in code_addresses:
        text[address - start] = memory[address]
    return start, end, bytes(text), len(code_addresses)


def _validate_code_span(functions: list[_Function], lines: list[_Line],
                        code_start: int, code_end: int) -> None:
    for function in functions:
        if not code_start <= function.address <= code_end:
            raise SymbolConversionError(
                f"function {function.name!r} address 0x{function.address:X} "
                "is outside the HEX code span"
            )
        if function.size and function.address + function.size - 1 > code_end:
            raise SymbolConversionError(
                f"function {function.name!r} extends outside the HEX code span"
            )
    for entry in lines:
        if not code_start <= entry.address <= code_end:
            raise SymbolConversionError(
                f"line entry {entry.file}:{entry.line} address 0x{entry.address:X} "
                "is outside the HEX code span"
            )


def _build_locals(parsed: _ParsedCdb, functions: list[_Function],
                  memory: dict[int, int], listings: set[Path], comp_dir: str,
                  ) -> dict[_Function, list[_Local]]:
    by_module: dict[str, list[Path]] = {}
    for listing in sorted(listings):
        module = listing.name.removesuffix(".rst").removesuffix(".c")
        by_module.setdefault(module, []).append(listing)
    cached = {path: read_listing(path) for paths in by_module.values() if len(paths) == 1
              for path in paths}
    linked_rows = {}
    ambiguous_rows = set()
    for rows in cached.values():
        for addr, row in rows.items():
            if addr in linked_rows:
                ambiguous_rows.add(addr)
            linked_rows[addr] = row
    for addr in ambiguous_rows:
        del linked_rows[addr]
    clobbers = call_clobbers(linked_rows, memory,
                            {func.address: func.address + func.size for func in functions})
    source_cache: dict[Path, str | None] = {}
    result: dict[_Function, list[_Local]] = {}
    declarations = parsed.stack_decls | parsed.register_decls
    for decl, integer_type in declarations.items():
        candidates = [func for func in functions if func.name == decl.function and func.size
                      and func.module in {None, decl.module}]
        matching = by_module.get(decl.module, [])
        locations = ()
        # A non-unique module/function or overlapping CDB allocation is not
        # sufficient to identify a local (including optimized slot reuse).
        if (len(candidates) == len(matching) == 1
                and len(parsed.local_scopes[decl.module, decl.function, decl.name]) == 1
                and not any(other != decl and other.module == decl.module
                            and other.function == decl.function
                            and (other.name == decl.name
                                 or (isinstance(decl, StackDecl) and isinstance(other, StackDecl)
                                     and other.offset < decl.offset + decl.size
                                     and decl.offset < other.offset + other.size))
                            for other in declarations)):
            func = candidates[0]
            listing = matching[0]
            inputs = func.address, func.address + func.size, cached[listing], memory
            if isinstance(decl, StackDecl):
                locations = tuple((start, end, bytes([0x70 + SPX_REGISTER]) + _sleb(offset))
                                  for start, end, offset in stack_ranges(decl, *inputs))
            else:
                source_lines = [line for line in parsed.lines
                                if func.address <= line.address < func.address + func.size
                                and Path(line.file).stem == decl.module]
                sources = {Path(comp_dir) / line.file for line in source_lines}
                text = None
                source_bounds = None
                if len(sources) == 1:
                    source = next(iter(sources))
                    if source not in source_cache:
                        try:
                            source_cache[source] = source.read_text(encoding="utf-8-sig")
                        except (OSError, UnicodeError):
                            source_cache[source] = None
                    text = source_cache[source]
                    source_bounds = (min(row.line for row in source_lines),
                                     max(row.line for row in source_lines))
                def expression(pieces):
                    parts = []
                    for piece in pieces:
                        location = (bytes([0x50 + piece.register]) if piece.spx_offset is None
                                    else bytes([0x70 + SPX_REGISTER]) + _sleb(piece.spx_offset))
                        parts.append(location + (b"\x93\x01" if len(pieces) > 1 else b""))
                    return b"".join(parts)

                locations = tuple((start, end, expression(pieces))
                                  for start, end, pieces in register_ranges(decl, *inputs,
                                                                          text, clobbers,
                                                                          source_bounds))
        if locations:
            result.setdefault(func, []).append(_Local(decl, integer_type, locations))
        else:
            _bump(parsed.counters, parsed.samples, "locals",
                  f"{decl.module}.{decl.function}${decl.name}: unverified location")
    return result


def _build_abbrev() -> bytes:
    out = bytearray()

    def table(code: int, tag: int, children: int,
              attrs: list[tuple[int, int]]) -> None:
        out.extend(_uleb(code))
        out.extend(_uleb(tag))
        out.append(children)
        for attr, form in attrs:
            out.extend(_uleb(attr))
            out.extend(_uleb(form))
        out.extend(b"\x00\x00")

    table(1, 0x11, 1, [
        (0x25, 0x08),  # DW_AT_producer, DW_FORM_string
        (0x13, 0x0B),  # DW_AT_language, DW_FORM_data1
        (0x03, 0x08),  # DW_AT_name, DW_FORM_string
        (0x1B, 0x08),  # DW_AT_comp_dir, DW_FORM_string
        (0x11, 0x01),  # DW_AT_low_pc, DW_FORM_addr
        (0x12, 0x01),  # DW_AT_high_pc, DW_FORM_addr
        (0x10, 0x06),  # DW_AT_stmt_list, DW_FORM_data4
    ])
    table(2, 0x24, 0, [
        (0x03, 0x08),  # DW_AT_name
        (0x0B, 0x0B),  # DW_AT_byte_size
        (0x3E, 0x0B),  # DW_AT_encoding
    ])
    table(3, 0x34, 0, [
        (0x03, 0x08),  # DW_AT_name
        (0x49, 0x13),  # DW_AT_type, DW_FORM_ref4
        (0x02, 0x0A),  # DW_AT_location, DW_FORM_block1
        (0x0B, 0x0B),  # DW_AT_byte_size
        (0x3E, 0x0B),  # DW_AT_encoding
        (0x3F, 0x0C),  # DW_AT_external, DW_FORM_flag
    ])
    table(4, 0x34, 0, [
        (0x03, 0x08),
        (0x49, 0x13),
        (0x02, 0x0A),
        (0x0B, 0x0B),
        (0x3E, 0x0B),
    ])
    table(5, 0x2E, 1, [  # DW_TAG_subprogram
        (0x03, 0x08),
        (0x11, 0x01),
        (0x12, 0x01),
        (0x3F, 0x0C),
    ])
    table(6, 0x34, 0, [
        (0x03, 0x08),
        (0x49, 0x13),
        (0x02, 0x06),  # DW_AT_location, DWARF2 .debug_loc section offset
    ])
    table(7, 0x01, 1, [(0x49, 0x13)])  # DW_TAG_array_type
    table(8, 0x21, 0, [(0x2F, 0x06)])  # DW_TAG_subrange_type, upper_bound
    table(9, 0x0F, 0, [(0x49, 0x13), (0x0B, 0x0B)])  # DW_TAG_pointer_type
    table(10, 0x13, 1, [(0x03, 0x08), (0x0B, 0x06)])  # DW_TAG_structure_type
    table(11, 0x17, 1, [(0x03, 0x08), (0x0B, 0x06)])  # DW_TAG_union_type
    member = [(0x03, 0x08), (0x49, 0x13), (0x38, 0x06)]
    table(12, 0x0D, 0, member)  # DW_TAG_member, byte offset
    table(13, 0x0D, 0, member + [(0x0B, 0x0B), (0x0D, 0x0B), (0x0C, 0x0B)])
    table(14, 0x15, 0, [(0x49, 0x13)])  # DW_TAG_subroutine_type
    table(15, 0x3B, 0, [(0x03, 0x08)])  # DW_TAG_unspecified_type (void)
    variable = [(0x03, 0x08), (0x49, 0x13), (0x02, 0x0A)]
    table(16, 0x34, 0, variable + [(0x3F, 0x0C)])
    table(17, 0x34, 0, variable)
    out.append(0)
    return bytes(out)


def _build_debug_info(cdb: Path, variables: list[_Variable], comp_dir: str,
                      code_start: int, code_end: int,
                      locals_by_function: dict[_Function, list[_Local]],
                      types: TypeTable) -> tuple[bytes, bytes]:
    dies = bytearray()
    locations = bytearray()
    dies.extend(_uleb(1))
    dies.extend(_cstring("STCForge experimental SDCC CDB converter"))
    dies.append(0x0C)  # DW_LANG_C99
    dies.extend(_cstring(cdb.stem))
    dies.extend(_cstring(comp_dir))
    dies.extend(struct.pack(">I", code_start))
    dies.extend(struct.pack(">I", code_end + 1))
    dies.extend(struct.pack(">I", 0))  # .debug_line offset

    roots = dict.fromkeys([var.type for var in variables] + [
        local.type for locals_ in locals_by_function.values() for local in locals_])
    type_offsets: dict[CdbType, int] = {}
    refs: list[tuple[int, CdbType]] = []
    pending = list(roots)

    def type_ref(type_: CdbType) -> None:
        refs.append((len(dies), type_))
        dies.extend(b"\x00" * 4)
        if type_ not in type_offsets:
            pending.append(type_)

    # Queue dependent types independently of DIE layout so recursive pointers
    # and forward references use the same nominal aggregate DIE.
    for type_ in pending:
        if type_ in type_offsets:
            continue
        type_offsets[type_] = 11 + len(dies)
        kind = type_.kind
        if kind == "base":
            dies.extend(_uleb(2) + _cstring(type_.name) + bytes((type_.size, type_.encoding)))
        elif kind in {"struct", "union"}:
            dies.extend(_uleb(10 if kind == "struct" else 11) + _cstring(type_.name))
            dies.extend(struct.pack(">I", type_.size))
            for member in types.members(type_):
                dies.extend(_uleb(13 if member.bit_size else 12) + _cstring(member.name))
                type_ref(member.type)
                dies.extend(struct.pack(">I", member.offset))
                if member.bit_size:
                    # CDB counts from the low bit; DWARF2 counts from the high bit.
                    bit_offset = member.type.size * 8 - member.bit_start - member.bit_size
                    dies.extend(bytes((member.type.size, member.bit_size, bit_offset)))
            dies.append(0)
        elif kind == "array":
            dies.extend(_uleb(7))
            type_ref(type_.target)
            dies.extend(_uleb(8) + struct.pack(">I", type_.count - 1) + b"\x00")
        elif kind == "pointer":
            dies.extend(_uleb(9))
            type_ref(type_.target)
            dies.append(type_.size)
        elif kind == "function":
            dies.extend(_uleb(14))
            type_ref(type_.target)
        elif kind == "void":
            dies.extend(_uleb(15) + _cstring("void"))
        else:
            raise SymbolConversionError(f"unsupported DWARF type {kind}")
    for offset, type_ in refs:
        struct.pack_into(">I", dies, offset, type_offsets[type_])

    for variable in sorted(variables, key=lambda item: (item.name, item.address,
                                                        item.scope)):
        external = variable.scope == "G"
        scalar = variable.type.kind == "base"
        dies.extend(_uleb((3 if external else 4) if scalar else (16 if external else 17)))
        dies.extend(_cstring(variable.name))
        dies.extend(struct.pack(">I", type_offsets[variable.type]))
        dies.append(5)
        dies.append(0x03)  # DW_OP_addr
        dies.extend(struct.pack(">I", variable.address))
        if scalar:
            dies.extend(bytes((variable.type.size, variable.type.encoding)))
        if external:
            dies.append(1)

    for func, locals_ in sorted(locals_by_function.items(), key=lambda item: item[0].address):
        dies.extend(_uleb(5))
        dies.extend(_cstring(func.name))
        dies.extend(struct.pack(">IIB", func.address, func.address + func.size, func.scope == "G"))
        for local in sorted(locals_, key=lambda item: item.decl.name):
            dies.extend(_uleb(6))
            dies.extend(_cstring(local.decl.name))
            dies.extend(struct.pack(">II", type_offsets[local.type], len(locations)))
            for start, end, expression in local.locations:
                locations.extend(struct.pack(">IIH", start - code_start, end - code_start,
                                             len(expression)) + expression)
            locations.extend(b"\x00" * 8)
        dies.append(0)

    dies.append(0)  # end of CU children
    body = struct.pack(">H", 2) + struct.pack(">I", 0) + bytes([4]) + bytes(dies)
    return struct.pack(">I", len(body)) + body, bytes(locations)


def _build_debug_line(lines: list[_Line]) -> bytes:
    files = sorted({entry.file for entry in lines})
    file_index = {name: index + 1 for index, name in enumerate(files)}

    header = bytearray()
    header.extend(bytes([1, 1, 0xFB, 14, 10]))  # DWARF2 line header
    header.extend(bytes([0, 1, 1, 1, 1, 0, 0, 0, 1]))
    header.append(0)  # empty include-directories table; use CU comp_dir
    for name in files:
        header.extend(_cstring(name))
        header.extend(_uleb(0))  # directory index 0: comp_dir
        header.extend(_uleb(0))  # mtime
        header.extend(_uleb(0))  # length
    header.append(0)  # end of file table

    program = bytearray()
    for name in files:
        rows = sorted({(entry.address, entry.line) for entry in lines
                       if entry.file == name})
        if not rows:
            continue
        first_address = rows[0][0]
        program.extend(b"\x00\x05\x02")
        program.extend(struct.pack(">I", first_address))
        program.append(4)  # DW_LNS_set_file
        program.extend(_uleb(file_index[name]))
        program.append(3)  # DW_LNS_advance_line: line is 1-based in CDB
        program.extend(_sleb(rows[0][1] - 1))
        program.append(1)  # DW_LNS_copy
        current_address = first_address
        current_line = rows[0][1]
        for address, line in rows[1:]:
            if address > current_address:
                program.append(2)  # DW_LNS_advance_pc
                program.extend(_uleb(address - current_address))
                current_address = address
            if line != current_line:
                program.append(3)  # DW_LNS_advance_line
                program.extend(_sleb(line - current_line))
                current_line = line
            program.append(1)  # DW_LNS_copy
        # Give the final row a non-empty address range.  If end_sequence has
        # the same address as the last row, GDB can report that address as the
        # sequence terminator instead of the source line itself.
        program.extend(b"\x02\x01")
        program.extend(b"\x00\x01\x01")  # DW_LNE_end_sequence

    unit_length = 2 + 4 + len(header) + len(program)
    return (struct.pack(">I", unit_length) + struct.pack(">H", 2)
            + struct.pack(">I", len(header)) + bytes(header) + bytes(program))


def _elf_symbols(cdb_name: str, functions: list[_Function],
                 variables: list[_Variable], code_start: int) -> tuple[list[_ElfSymbol], int]:
    local_prefix = [
        _ElfSymbol(cdb_name, 0, 0, 0, 4, 0xFFF1),  # STT_FILE, SHN_ABS
        _ElfSymbol("", code_start, 0, 0, 3, 1),     # STT_SECTION, .text
    ]
    local_body: list[_ElfSymbol] = []
    global_body: list[_ElfSymbol] = []
    for function in functions:
        bind = 1 if function.scope == "G" else 0
        symbol = _ElfSymbol(function.name, function.address, function.size,
                            bind, 2, 1)
        (global_body if bind else local_body).append(symbol)
    for variable in variables:
        bind = 1 if variable.scope == "G" else 0
        symbol = _ElfSymbol(variable.name, variable.address, variable.type.size,
                            bind, 1, 0xFFF1)
        (global_body if bind else local_body).append(symbol)

    local_body.sort(key=lambda item: (item.name, item.value))
    global_body.sort(key=lambda item: (item.name, item.value))
    symbols = ([_ElfSymbol("", 0, 0, 0, 0, 0)] + local_prefix + local_body
               + global_body)
    first_global = 1 + len(local_prefix) + len(local_body)
    return symbols, first_global


def _build_elf(text: bytes, text_address: int, abbrev: bytes, info: bytes,
               line: bytes, symbols: list[_ElfSymbol], first_global: int,
               locations: bytes = b"") -> bytes:
    strtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {"": 0}
    for symbol in symbols:
        if symbol.name and symbol.name not in name_offsets:
            name_offsets[symbol.name] = len(strtab)
            strtab.extend(_cstring(symbol.name))

    symtab = bytearray()
    for symbol in symbols:
        info_byte = (symbol.bind << 4) | symbol.kind
        symtab.extend(struct.pack(">IIIBBH", name_offsets.get(symbol.name, 0),
                                  symbol.value, symbol.size, info_byte, 0,
                                  symbol.shndx))

    section_names = [".text", ".debug_abbrev", ".debug_info", ".debug_line",
                     ".symtab", ".strtab", ".shstrtab"]
    if locations:
        section_names.append(".debug_loc")
    shstrtab = bytearray(b"\x00")
    sh_name_offsets: dict[str, int] = {}
    for name in section_names:
        sh_name_offsets[name] = len(shstrtab)
        shstrtab.extend(_cstring(name))

    blob = bytearray(b"\x00" * 52)

    def append(data: bytes, alignment: int = 1) -> int:
        while len(blob) % alignment:
            blob.append(0)
        offset = len(blob)
        blob.extend(data)
        return offset

    text_offset = append(text, 1)
    abbrev_offset = append(abbrev, 1)
    info_offset = append(info, 1)
    line_offset = append(line, 1)
    location_offset = append(locations, 1)
    symtab_offset = append(bytes(symtab), 4)
    strtab_offset = append(bytes(strtab), 1)
    shstrtab_offset = append(bytes(shstrtab), 1)
    while len(blob) % 4:
        blob.append(0)
    shoff = len(blob)

    def section_header(name: str, kind: int, flags: int, address: int,
                       offset: int, size: int, link: int = 0, info_value: int = 0,
                       alignment: int = 1, entsize: int = 0) -> bytes:
        return struct.pack(">IIIIIIIIII", sh_name_offsets[name], kind, flags,
                           address, offset, size, link, info_value, alignment,
                           entsize)

    headers = [
        b"\x00" * 40,
        section_header(".text", 1, 0x6, text_address, text_offset, len(text)),
        section_header(".debug_abbrev", 1, 0, 0, abbrev_offset, len(abbrev)),
        section_header(".debug_info", 1, 0, 0, info_offset, len(info)),
        section_header(".debug_line", 1, 0, 0, line_offset, len(line)),
        section_header(".symtab", 2, 0, 0, symtab_offset, len(symtab), 6,
                       first_global, 4, 16),
        section_header(".strtab", 3, 0, 0, strtab_offset, len(strtab)),
        section_header(".shstrtab", 3, 0, 0, shstrtab_offset, len(shstrtab)),
    ]
    if locations:
        headers.append(section_header(".debug_loc", 1, 0, 0, location_offset, len(locations)))
    blob.extend(b"".join(headers))

    ident = b"\x7fELF" + bytes([1, 2, 1, 0, 0]) + b"\x00" * 7
    header = ident + struct.pack(">HHIIIIIHHHHHH", 2, 0, 1, text_address, 0,
                                 shoff, 0, 52, 0, 0, 40, len(headers), 7)
    blob[:52] = header
    return bytes(blob)


def _source_comp_dir(source_root: Path | None) -> str:
    if source_root is None:
        return "."
    root = Path(source_root)
    if not root.is_dir():
        raise SymbolConversionError(f"source_root is not a directory: {root}")
    return str(root.resolve()).replace("\\", "/")


def _make_limitations(counters: dict[str, int]) -> list[str]:
    limitations = [
        "调试信息由 STCForge experimental 转换器生成，不代表完整 CDB 支持。",
        "支持常见 CDB 标量及复合类型；局部变量的位置须经链接后的汇编列表验证。",
        "不为参数或无法验证位置的局部变量生成位置。",
        "S:C 宏/常量记录不映射，不猜测其地址。",
        "局部变量仅用于当前函数栈帧；不生成调用栈展开信息。",
        "SFR 只使用 GDB 虚拟地址 0x10000000+raw，不代表芯片具有 32 位物理地址总线。",
        "已知但未使用的 L:A 汇编地址记录和 L:L 局部地址记录不计入损坏记录。",
    ]
    labels = {
        "locals": "局部变量声明",
        "unknown_types": "类型或布局无法确认",
        "bit_variables": "位变量/位寄存器",
        "unsupported_storage": "未知存储类别",
        "macros": "S:C 宏/常量",
        "missing_variable_address": "缺少 L:G/L:F 地址的全局变量",
        "missing_function_address": "缺少 L:G/L:F 地址的函数",
        "ambiguous_file_statics": "跨模块同名的文件静态变量",
        "malformed_records": "无法解析的已知记录",
    }
    skipped = []
    for key, label in labels.items():
        count = counters.get(key, 0)
        if count:
            skipped.append(f"{count} 条{label}")
    if skipped:
        limitations.append("本次跳过：" + "、".join(skipped) + "。")
    return limitations


def _resolve_sources(lines: list[_Line], source_dirs: list[Path]) -> list[_Line]:
    """只在调用者指定的源码目录中查找，避免误选其他例程的同名文件。"""
    directories = [Path(folder).resolve() for folder in source_dirs]
    for folder in directories:
        if not folder.is_dir():
            raise SymbolConversionError(f"source directory does not exist: {folder}")
    resolved = {}
    for name in {entry.file for entry in lines}:
        path = Path(name)
        candidates = ({path.resolve()} if path.is_absolute() and path.is_file() else
                      {(folder / path).resolve() for folder in directories
                       if (folder / path).is_file()})
        if len(candidates) != 1:
            detail = ", ".join(sorted(str(item) for item in candidates)) or "no match"
            raise SymbolConversionError(f"source file {name!r} must resolve uniquely: {detail}")
        resolved[name] = next(iter(candidates)).as_posix()
    return [_Line(resolved[entry.file], entry.line, entry.address) for entry in lines]


def convert(cdb: Path, hex: Path, output: Path,
            source_root: Path | None = None,
            source_dirs: list[Path] | None = None,
            listing_dirs: list[Path] | None = None) -> dict[str, Any]:
    """Convert one SDCC CDB/HEX pair into a minimal ELF32 debug image.

    Args:
        cdb: SDCC ``.cdb`` file produced with ``--debug``.
        hex: Intel HEX image from the same link.
        output: Destination ELF path.
        source_root: Optional directory used as DWARF ``DW_AT_comp_dir``.
        source_dirs: Explicit source directories; resolve CDB file names uniquely.
        listing_dirs: Additional directories searched recursively for linked .rst files.

    Returns:
        A JSON-serializable summary dictionary.  The function raises
        :class:`SymbolConversionError` rather than emitting guessed addresses.
    """
    cdb = Path(cdb)
    hex_path = Path(hex)
    output = Path(output)
    if not cdb.is_file():
        raise FileNotFoundError(f"CDB file not found: {cdb}")
    if not hex_path.is_file():
        raise FileNotFoundError(f"HEX file not found: {hex_path}")

    comp_dir = _source_comp_dir(source_root)
    memory = read_hex(hex_path)
    parsed = _parse_cdb(cdb)
    if source_dirs:
        parsed.lines = _resolve_sources(parsed.lines, source_dirs)
    functions = _build_functions(parsed)
    map_functions = _map_functions(cdb.with_suffix(".map"), parsed, functions, memory)
    functions.extend(map_functions)
    variables = _build_variables(parsed)
    variables = _filter_ambiguous_file_statics(parsed, variables)
    _check_global_collisions(functions, variables)

    code_start, code_end, text, hex_code_bytes = _make_text(memory)
    _validate_code_span(functions, parsed.lines, code_start, code_end)

    listings = set(cdb.resolve().parent.glob("*.rst"))
    for folder in listing_dirs or []:
        listings.update(Path(folder).resolve().rglob("*.rst"))
    locals_by_function = _build_locals(parsed, functions, memory, listings, comp_dir)
    abbrev = _build_abbrev()
    info, locations = _build_debug_info(cdb, variables, comp_dir, code_start, code_end,
                                        locals_by_function, parsed.types)
    line = _build_debug_line(parsed.lines)
    symbols, first_global = _elf_symbols(cdb.name, functions, variables, code_start)
    elf = _build_elf(text, code_start, abbrev, info, line, symbols, first_global, locations)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(elf)

    files = sorted({entry.file for entry in parsed.lines})
    skipped_keys = [
        "locals", "unknown_types", "bit_variables", "unsupported_storage",
        "macros", "missing_variable_address", "missing_function_address",
        "ambiguous_file_statics", "malformed_records",
    ]
    duplicate_keys = [
        "duplicate_declarations", "duplicate_lines", "duplicate_address_records",
    ]
    result: dict[str, Any] = {
        "status": "ok",
        "output": str(output),
        "cdb": str(cdb),
        "hex": str(hex_path),
        "source_root": str(Path(source_root).resolve()) if source_root else None,
        "elf": {
            "class": 32,
            "data": "big",
            "machine": "EM_NONE",
            "machine_id": 0,
        },
        "entry": code_start,
        "text": {
            "start": code_start,
            "end": code_end,
            "size": len(text),
            "hex_bytes": hex_code_bytes,
        },
        "functions": len(functions),
        "map_functions": len(map_functions),
        "globals": sum(variable.scope == "G" for variable in variables),
        "file_statics": sum(variable.scope == "F" for variable in variables),
        "sfr": sum(variable.storage == "I" for variable in variables),
        "variables": len(variables),
        "stack_locals": sum(isinstance(local.decl, StackDecl)
                            for items in locals_by_function.values() for local in items),
        "register_locals": sum(isinstance(local.decl, RegisterDecl)
                               for items in locals_by_function.values() for local in items),
        "lines": len(parsed.lines),
        "files": len(files),
        "known_ignored": {
            "assembly_records": parsed.counters.get("assembly_records", 0),
            "local_address_records": parsed.counters.get("local_address_records", 0),
        },
        "file_static_ambiguities": {
            "name": "ambiguous_file_statics",
            "count": parsed.counters.get("ambiguous_file_statics", 0),
            "policy": "skip_all_same_name",
            "note": "单 CU 下按名字查询会歧义；跨模块同名静态变量全部跳过。",
        },
        "skipped": {key: parsed.counters.get(key, 0) for key in skipped_keys},
        "duplicates": {key: parsed.counters.get(key, 0) for key in duplicate_keys},
        "samples": {key: value for key, value in parsed.samples.items() if value},
        "limitations": _make_limitations(parsed.counters),
    }
    return result


def main(argv: list[str] | None = None) -> int:
    """Small module-level command for development and CLI integration."""
    parser = argparse.ArgumentParser(
        description="Convert SDCC CDB + Intel HEX to a minimal MCS-251 debug ELF"
    )
    parser.add_argument("--cdb", type=Path, required=True)
    parser.add_argument("--hex", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--source-dir", type=Path, action="append", default=[])
    parser.add_argument("--listing-dir", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    try:
        result = convert(args.cdb, args.hex, args.output, args.source_root, args.source_dir,
                         args.listing_dir)
    except (OSError, ValueError) as error:
        print(f"symbol conversion failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
