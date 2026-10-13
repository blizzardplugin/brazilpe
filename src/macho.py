"""Bounded Mach-O reader and segment insertion for the fingerprinted ARM64 build."""
import struct

SEGMENT = 0x19
LINKEDIT_DATA = {0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034}


def align(value, page):
    return (value + page - 1) // page * page


class MachO:
    def __init__(self, data):
        self.raw = bytes(data)
        if len(data) < 32:
            raise ValueError("Truncated Mach-O header")
        self.header = struct.unpack_from("<8I", data)
        if self.header[0] != 0xFEEDFACF or self.header[1] != 0x100000C:
            raise ValueError("Expected thin little-endian ARM64 Mach-O")
        self.commands, self.segments, self.sections = [], [], []
        pos = 32
        for _ in range(self.header[4]):
            if pos + 8 > len(data):
                raise ValueError("Truncated load command")
            cmd, size = struct.unpack_from("<II", data, pos)
            if size < 8 or size % 8 or pos + size > len(data):
                raise ValueError("Invalid load-command size")
            c = bytes(data[pos:pos + size])
            self.commands.append((cmd, c))
            if cmd == SEGMENT:
                fields = struct.unpack_from("<II16sQQQQiiII", c)
                _, _, name, va, vs, fo, fs, _, _, count, _ = fields
                if 72 + count * 80 != size:
                    raise ValueError("Invalid segment section count")
                if fo + fs > len(data):
                    raise ValueError("Segment extends beyond file")
                self.segments.append(dict(name=name.rstrip(b"\0").decode(), va=va,
                                          vs=vs, fo=fo, fs=fs))
                for n in range(count):
                    s = struct.unpack_from("<16s16sQQIIIIIIII", c, 72 + n * 80)
                    self.sections.append(dict(name=s[0].rstrip(b"\0").decode(),
                                              segment=s[1].rstrip(b"\0").decode(),
                                              va=s[2], size=s[3], offset=s[4],
                                              flags=s[8], reserved1=s[9], reserved2=s[10]))
            if cmd in {0x21, 0x2C} and struct.unpack_from("<I", c, 16)[0]:
                raise ValueError("Executable is encrypted; modification is blocked")
            pos += size
        if pos != 32 + self.header[5]:
            raise ValueError("Load-command table size mismatch")

    def command(self, kind):
        matches = [c for k, c in self.commands if k == kind]
        if len(matches) != 1:
            raise ValueError(f"Expected one load command {kind:#x}")
        return matches[0]

    def offset(self, address, length=1):
        for s in self.segments:
            if s["va"] <= address and address + length <= s["va"] + s["fs"]:
                return s["fo"] + address - s["va"]
        raise ValueError(f"Address {address:#x} is not file-backed")

    def read(self, address, length):
        off = self.offset(address, length)
        return self.raw[off:off + length]

    def import_stubs(self):
        _, _, symoff, count, stroff, strsize = struct.unpack("<6I", self.command(2))
        d = struct.unpack("<20I", self.command(0xB))
        indirectoff, indirectcount = d[14], d[15]
        if symoff + count * 16 > len(self.raw) or stroff + strsize > len(self.raw):
            raise ValueError("Symbol table is outside the file")
        if indirectoff + indirectcount * 4 > len(self.raw):
            raise ValueError("Indirect symbol table is outside the file")
        names = []
        strings = self.raw[stroff:stroff + strsize]
        for n in range(count):
            idx = struct.unpack_from("<I", self.raw, symoff + n * 16)[0]
            if idx >= len(strings):
                raise ValueError("Invalid symbol string index")
            names.append(strings[idx:].split(b"\0", 1)[0].decode("ascii"))
        result = {}
        for s in self.sections:
            if s["flags"] & 0xFF != 8:
                continue
            stride = s["reserved2"]
            if stride != 12 or s["size"] % stride:
                raise ValueError("Unsupported ARM64 stub layout")
            for n in range(s["size"] // stride):
                idx = s["reserved1"] + n
                if idx >= indirectcount:
                    raise ValueError("Stub indirect index outside table")
                sym = struct.unpack_from("<I", self.raw, indirectoff + idx * 4)[0]
                if sym < len(names):
                    result[names[sym]] = s["va"] + n * stride
        return result

    def rebased_pointers(self):
        c = self.command(0x80000022)
        offset, size = struct.unpack_from("<II", c, 8)
        data = self.raw[offset:offset + size]
        pos, address, kind, result = 0, None, None, set()

        def uleb():
            nonlocal pos
            value, shift = 0, 0
            while pos < len(data) and shift < 64:
                v = data[pos]; pos += 1
                value |= (v & 127) << shift
                if not v & 128:
                    return value
                shift += 7
            raise ValueError("Invalid rebase ULEB128")

        def emit(count, skip=0):
            nonlocal address
            if kind != 1 or address is None or count > len(self.raw) // 8:
                raise ValueError("Unsupported or unbounded rebase")
            for _ in range(count):
                self.offset(address, 8)
                result.add(address)
                address += 8 + skip

        while pos < len(data):
            b = data[pos]; pos += 1
            op, imm = b & 0xF0, b & 15
            if op == 0:
                break
            if op == 0x10:
                kind = imm
            elif op == 0x20:
                if imm >= len(self.segments):
                    raise ValueError("Rebase segment index outside table")
                address = self.segments[imm]["va"] + uleb()
            elif op == 0x30:
                address += uleb()
            elif op == 0x40:
                address += imm * 8
            elif op == 0x50:
                emit(imm)
            elif op == 0x60:
                emit(uleb())
            elif op == 0x70:
                emit(1); address += uleb()
            elif op == 0x80:
                count, skip = uleb(), uleb(); emit(count, skip)
            else:
                raise ValueError(f"Unsupported rebase opcode {op:#x}")
        return result


def segment_command(name, va, fo, page, protection, sections):
    name_bytes = name.encode().ljust(16, b"\0")
    out = struct.pack("<II16sQQQQiiII", SEGMENT, 72 + 80 * len(sections),
                      name_bytes, va, page, fo, page, protection, protection,
                      len(sections), 0)
    for sect_name, relative, size, flags in sections:
        out += struct.pack("<16s16sQQIIIIIIII", sect_name.encode().ljust(16, b"\0"),
                           name_bytes, va + relative, size, fo + relative, 2,
                           0, 0, flags, 0, 0, 0)
    return out


def insert_segments(original, code, state, page):
    """Keep original code/data addresses fixed and shift LINKEDIT metadata only."""
    m = MachO(original)
    link = next(s for s in m.segments if s["name"] == "__LINKEDIT")
    if m.segments[-1]["name"] != "__LINKEDIT" or link["fo"] % page or link["va"] % page:
        raise ValueError("Unsupported LINKEDIT alignment/layout")
    if len(code) != page or len(state) != page:
        raise ValueError("Injected segment must occupy one page")
    if any(s["name"].startswith("__MCPE") for s in m.segments):
        raise ValueError("This executable is already modified")
    delta = page * 2
    commands = []
    for kind, raw in m.commands:
        if kind == 0x1D:
            continue  # The output is intentionally unsigned and must be re-signed.
        c = bytearray(raw)

        def shift(at):
            value = struct.unpack_from("<I", c, at)[0]
            if value >= link["fo"] and value:
                struct.pack_into("<I", c, at, value + delta)

        if kind == SEGMENT and raw[8:24].rstrip(b"\0") == b"__LINKEDIT":
            commands.append(segment_command("__MCPEHB", link["va"], link["fo"], page, 5,
                                             [("__text", 0, 0x1800, 0x80000400),
                                              ("__cstring", 0x2000, 0x1000, 2)]))
            commands.append(segment_command("__MCPECFG", link["va"] + page,
                                             link["fo"] + page, page, 3,
                                             [("__data", 0, 64, 0)]))
            struct.pack_into("<Q", c, 24, link["va"] + delta)
            struct.pack_into("<Q", c, 40, link["fo"] + delta)
        elif kind == 2:
            shift(8); shift(16)
        elif kind == 0xB:
            for at in [32, 40, 48, 56, 64, 72]:
                shift(at)
        elif kind in {0x22, 0x80000022}:
            for at in range(8, 48, 8):
                shift(at)
        elif kind in LINKEDIT_DATA or kind == 0x16:
            shift(8)
        commands.append(bytes(c))
    table = b"".join(commands)
    earliest = min(s["offset"] for s in m.sections if s["offset"])
    old_end = 32 + m.header[5]
    new_end = 32 + len(table)
    if new_end > earliest or any(original[old_end:new_end]):
        raise ValueError("Not enough empty load-command padding")
    data = bytearray(original[:link["fo"]] + code + state + original[link["fo"]:])
    data[32:new_end] = table
    struct.pack_into("<II", data, 16, len(commands), len(table))
    return data
