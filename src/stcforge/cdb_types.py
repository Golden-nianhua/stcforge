"""Resolve SDCC MCS-251 CDB type records without using host C layouts."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class CdbType:
    size: int
    kind: str
    name: str = ""
    encoding: int = 0
    target: "CdbType | None" = None
    count: int = 0
    module: str = ""


@dataclass(frozen=True)
class Member:
    name: str
    offset: int
    type: CdbType
    bit_start: int = 0
    bit_size: int = 0


_TYPE = re.compile(r"\{(\d+)\}(.+)")
_TAG = re.compile(r"T:F(.+)\$([^$\[]+)\[(.*)\]")
_MEMBER = re.compile(r"\(\{(\d+)\}S:S\$([^$]+)\$\d+_\d+\$\d+\((\{\d+\}[^)]*)\),Z,\d+,\d+\)")
_BITFIELD = re.compile(r"SB(\d+)\$(\d+):([SU])")
_ARRAY = re.compile(r"DA(\d+)d")
_POINTER_SIZES = {"DD": 1, "DI": 1, "DX": 3, "DC": 3, "DG": 3}
_INTEGER = {"SC": (1, "char"), "SS": (2, "short"), "SI": (2, "int"),
            "SL": (4, "long"), "SLL": (8, "long long")}


class TypeTable:
    def __init__(self, text: str):
        self.tags: dict[tuple[str, str], set[str]] = {}
        self.layouts: dict[CdbType, tuple[Member, ...] | None] = {}
        for line in text.splitlines():
            if match := _TAG.fullmatch(line.strip()):
                self.tags.setdefault((match[1], match[2]), set()).add(match[3])

    def _tag(self, module: str, name: str) -> CdbType | None:
        key = (module, name)
        if key not in self.tags:
            matches = [entry for entry in self.tags if entry[1] == name]
            if len(matches) != 1:
                return None
            key, = matches
        definitions = self.tags[key]
        if len(definitions) != 1:
            return None
        definition, = definitions
        members = list(_MEMBER.finditer(definition))
        if not members or "".join(row[0] for row in members) != definition:
            return None
        size = max(int(row[1]) + int(_TYPE.fullmatch(row[3])[1]) for row in members)
        # CDB emits ST for both struct and union. Overlapping non-bitfield
        # members at offset zero distinguish unions with multiple alternatives.
        ordinary_at_zero = sum(row[1] == "0" and "$" not in row[3] for row in members)
        return CdbType(size, "union" if ordinary_at_zero > 1 else "struct",
                       name, module=key[0])

    def _parse(self, tokens: list[str], module: str, size: int | None) -> CdbType | None:
        code = tokens[0]
        if len(tokens) > 1:
            if array := _ARRAY.fullmatch(code):
                count = int(array[1])
                if not count or (size is not None and size % count):
                    return None
                target = self._parse(tokens[1:], module, None if size is None else size // count)
                if target and target.size:
                    return CdbType(target.size * count, "array", target=target, count=count)
            elif code in _POINTER_SIZES:
                pointer_size = _POINTER_SIZES[code]
                if size not in (None, pointer_size):
                    return None
                target = self._parse(tokens[1:], module, None)
                if target:
                    return CdbType(pointer_size, "pointer", target=target)
            elif code == "DF" and size is None:
                target = self._parse(tokens[1:], module, None)
                if target:
                    return CdbType(0, "function", target=target)
            return None

        match = re.fullmatch(r"(S[^:]+)(?::([SU]))?", code)
        if not match:
            return None
        code, sign = match.groups()
        signed = sign != "U"
        if code.startswith("ST"):
            tag = self._tag(module, code[2:])
            return tag if tag and size in (None, tag.size) else None
        if code == "SV":
            return CdbType(0, "void", "void") if size in (None, 0) else None
        if code == "SF":
            return CdbType(4, "base", "float", 0x04) if size in (None, 4) else None
        if code == "SB":
            return CdbType(1, "base", "bool", 0x02) if size in (None, 1) else None
        if code not in _INTEGER:
            return None
        width, name = _INTEGER[code]
        if code == "SI" and size == 8:
            # This port emits SI, not SLL, for 64-bit long long.
            width, name = 8, "long long"
        if size not in (None, width):
            return None
        encoding = (0x06 if signed else 0x08) if code == "SC" else (0x05 if signed else 0x07)
        if code == "SC" and signed:
            name = "signed char"
        elif not signed:
            name = f"unsigned {name}"
        return CdbType(width, "base", name, encoding)

    def members(self, type_: CdbType) -> tuple[Member, ...] | None:
        if type_ in self.layouts:
            return self.layouts[type_]
        raw, = self.tags[type_.module, type_.name]
        self.layouts[type_] = None
        members = []
        occupied = []
        names = set()
        for row in _MEMBER.finditer(raw):
            offset, name = int(row[1]), row[2]
            size, spelling = _TYPE.fullmatch(row[3]).groups()
            size = int(size)
            start = width = 0
            if bits := _BITFIELD.fullmatch(spelling):
                start, width = int(bits[1]), int(bits[2])
                signed = bits[3] == "S"
                if size not in {1, 2, 4} or not width or start + width > size * 8:
                    return None
                base = {1: "char", 2: "int", 4: "long"}[size]
                member_type = CdbType(size, "base", f"{'signed' if signed else 'unsigned'} {base}",
                                      (0x06 if signed else 0x08) if size == 1
                                      else (0x05 if signed else 0x07))
            else:
                member_type = self._parse(spelling.split(","), type_.module, size)
            if (member_type is None or not size or size > 0x1000000
                    or offset + size > type_.size or name in names):
                return None
            names.add(name)
            bit_low = offset * 8 + start
            occupied.append((bit_low, bit_low + (width or size * 8)))
            members.append(Member(name, offset, member_type, start, width))
        if type_.kind == "struct":
            occupied.sort()
            if any(end > next_start for (_, end), (next_start, _) in zip(occupied, occupied[1:])):
                return None
        elif any(member.offset != 0 for member in members):
            return None
        self.layouts[type_] = tuple(members)
        return self.layouts[type_]

    def parse(self, text: str, module: str) -> CdbType | None:
        match = _TYPE.fullmatch(text)
        if not match or int(match[1]) > 0x1000000:
            return None
        tokens = match[2].split(",")
        if len(tokens) > 32:
            return None
        root = self._parse(tokens, module, int(match[1]))
        if root is None or not root.size:
            return None
        visited = set()
        pending = [root]
        while pending:
            type_ = pending.pop()
            if type_ in visited:
                continue
            visited.add(type_)
            if type_.target:
                pending.append(type_.target)
            if type_.kind in {"struct", "union"}:
                members = self.members(type_)
                if members is None:
                    return None
                pending.extend(member.type for member in members)
        return root
