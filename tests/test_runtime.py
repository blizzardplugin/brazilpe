"""Execute the generated ARM64 helpers; emulate only their existing C imports."""
import ctypes
import importlib.util
import json
import math
import os
import struct
import sys
import unittest
import zipfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mcpe_build", ROOT / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
PROFILE = json.loads((ROOT / "profile.json").read_text())
IPA = os.environ.get("MCPE_TEST_IPA")
LIBC = ctypes.CDLL(None)
LIBC.sscanf.restype = ctypes.c_int


class NativeHarness:
    def __init__(self, raw, config=None, slide=0):
        self.original = build.MachO(raw)
        defaults = build.parse_config((ROOT / "hitbox.cfg").read_text(), PROFILE)
        self.patched, self.report, self.imports = build.patch_executable(raw, PROFILE, defaults)
        m = build.MachO(self.patched)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.slide = slide
        for seg in m.segments:
            if not seg["va"] or not seg["vs"]:
                continue
            size = (seg["vs"] + 4095) & ~4095
            self.uc.mem_map(seg["va"] + slide, size)
            if seg["fs"]:
                self.uc.mem_write(seg["va"] + slide,
                                  self.patched[seg["fo"]:seg["fo"] + seg["fs"]])
        self.stack = 0x70000000
        self.uc.mem_map(self.stack, 0x10000)
        self.uc.mem_map(0x71000000, 0x10000)
        self.uc.mem_write(0x71000000, b"/private/var/mobile/Containers/Data/Application/TEST\0")
        self.path = "/private/var/mobile/Containers/Data/Application/TEST/Documents/mcpe-hitbox/hitbox.cfg"
        self.files = {} if config is None else {self.path: config.encode()}
        self.handles, self.clock, self.calls = {}, 100, []
        self.return_pc = 0x71001000
        self.uc.mem_write(self.return_pc, build.assemble("nop", self.return_pc))
        self.lookup = {v + slide: n.lstrip("_") for n, v in self.imports.items()
                       if n.lstrip("_") in build.REQUIRED_IMPORTS}
        self.state = next(s["va"] for s in m.segments if s["name"] == "__MCPECFG") + slide
        self.uc.hook_add(UC_HOOK_CODE, self.on_instruction)

    def cstring(self, address, bound=1024):
        data = bytearray()
        for off in range(bound):
            byte = self.uc.mem_read(address + off, 1)[0]
            if not byte:
                return bytes(data)
            data.append(byte)
        raise AssertionError("Unbounded C string")

    def on_instruction(self, uc, address, size, user):
        if address == self.return_pc:
            uc.emu_stop(); return
        name = self.lookup.get(address)
        if name is None:
            return
        args = [uc.reg_read(r) for r in [UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                       UC_ARM64_REG_X2, UC_ARM64_REG_X3]]
        self.calls.append(name)
        result = 0
        if name == "time":
            result = self.clock
        elif name == "getenv":
            assert self.cstring(args[0]) == b"HOME"
            result = 0x71000000
        elif name == "mkdir":
            assert self.cstring(args[0]).decode() == self.path.rsplit("/", 1)[0]
            assert args[1] == 493
        elif name == "fopen":
            path, mode = self.cstring(args[0]).decode(), self.cstring(args[1]).decode()
            assert path == self.path
            if (mode == "rb" and path in self.files) or (mode == "wx" and path not in self.files):
                result = 0x80000000 + len(self.handles) * 16
                self.handles[result] = (path, mode)
                if mode == "wx":
                    self.files[path] = b""
        elif name == "fread":
            path, mode = self.handles[args[3]]
            assert mode == "rb" and args[1] == 1 and args[2] == 127
            data = self.files[path][:args[2]]
            uc.mem_write(args[0], data)
            result = len(data)
        elif name == "fwrite":
            path, mode = self.handles[args[3]]
            assert mode == "wx" and args[1] == 1
            self.files[path] = bytes(uc.mem_read(args[0], args[2]))
            result = args[2]
        elif name == "fclose":
            self.handles.pop(args[0])
        elif name == "sscanf":
            data, fmt = self.cstring(args[0], 128), self.cstring(args[1])
            # Apple ARM64 variadic arguments are on SP, rather than in x2..x5.
            pointers = struct.unpack("<4Q", bytes(uc.mem_read(uc.reg_read(UC_ARM64_REG_SP), 32)))
            values = [ctypes.c_int(), ctypes.c_float(), ctypes.c_float(), ctypes.c_char()]
            result = LIBC.sscanf(ctypes.c_char_p(data), ctypes.c_char_p(fmt),
                                 *(ctypes.byref(v) for v in values))
            for pointer, value in zip(pointers, values):
                uc.mem_write(pointer, ctypes.string_at(ctypes.byref(value), ctypes.sizeof(value)))
        else:
            raise AssertionError(name)
        uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))
        # C functions may overwrite these registers; retaining all of them would hide ABI bugs.
        for reg in [UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10]:
            uc.reg_write(reg, 0xDEAD)
        for reg in [UC_ARM64_REG_Q0, UC_ARM64_REG_Q1, UC_ARM64_REG_Q2]:
            uc.reg_write(reg, 0xBEEF)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def run(self, helper, input_float=6.0):
        uc = self.uc
        sp = self.stack + 0x8000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_X30, self.return_pc)
        protected = [UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
                     UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
                     UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
                     UC_ARM64_REG_X28, UC_ARM64_REG_X29]
        for n, reg in enumerate(protected):
            uc.reg_write(reg, 0x12340000 + n)
        for n, reg in enumerate([UC_ARM64_REG_D8, UC_ARM64_REG_D9, UC_ARM64_REG_D10]):
            uc.reg_write(reg, 0x76540000 + n)
        bits = struct.unpack("<I", struct.pack("<f", input_float))[0]
        uc.reg_write(UC_ARM64_REG_Q0, bits)
        address = int(self.report["helpers"][helper]["address"], 0) + self.slide
        uc.emu_start(address, self.return_pc + 4, count=50000)
        assert uc.reg_read(UC_ARM64_REG_PC) == self.return_pc, "Helper did not return"
        assert uc.reg_read(UC_ARM64_REG_SP) == sp, "Stack was not restored"
        for n, reg in enumerate(protected):
            assert uc.reg_read(reg) == 0x12340000 + n, "Callee-saved integer register changed"
        for n, reg in enumerate([UC_ARM64_REG_D8, UC_ARM64_REG_D9, UC_ARM64_REG_D10]):
            if helper == "range" and n == 0:
                continue  # The original inline instruction deliberately writes v8.
            assert uc.reg_read(reg) == 0x76540000 + n, "Callee-saved float register changed"
        return struct.unpack("<f", struct.pack("<I", uc.reg_read(UC_ARM64_REG_S0)))[0]

    def settings(self):
        return struct.unpack("<fff", bytes(self.uc.mem_read(self.state, 12)))


@unittest.skipUnless(IPA, "Set MCPE_TEST_IPA to the inspected IPA")
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(IPA) as z:
            cls.raw = z.read("Payload/minecraftpe.app/minecraftpe")

    def test_live_reload_and_preserved_registers(self):
        h = NativeHarness(self.raw, "enabled=1\nradius=0.75\nreach=6\n")
        h.run("range")
        self.assertEqual(h.settings(), (0.75, 6.0, 1.0))
        self.assertEqual(h.run("radius"), 0.75)
        count = len(h.calls)
        h.run("range")
        self.assertEqual(h.calls[count:], ["time"])
        h.files[h.path] = b"enabled=1\nradius=2.5\nreach=9\n"
        h.clock += 1; h.run("range")
        self.assertEqual(h.settings(), (2.5, 9.0, 2.5))
        h.run("broad")
        self.assertEqual(struct.unpack("<3f", bytes(h.uc.mem_read(h.stack + 0x8108, 12))), (2.5,) * 3)
        self.assertEqual(h.run("cap_s0"), 9)
        h.run("cap_s1", 2)
        self.assertEqual(struct.unpack("<f", struct.pack("<I", h.uc.reg_read(UC_ARM64_REG_S1)))[0], 9)

    def test_first_launch_creates_config_without_menu(self):
        h = NativeHarness(self.raw)
        h.run("range")
        self.assertEqual(h.files[h.path], b"enabled=1\nradius=0.75\nreach=6\n")
        self.assertEqual(h.settings(), (0.75, 6, 1))
        self.assertEqual(h.handles, {})

    def test_invalid_and_disabled_config_restore_original_values(self):
        for config in ["enabled=0 radius=1 reach=6", "enabled=2 radius=1 reach=6",
                       "enabled=1 radius=nan reach=6", "enabled=1 radius=inf reach=6",
                       "enabled=1 radius=9 reach=6", "enabled=1 radius=0.01 reach=6",
                       "enabled=1 radius=1 reach=13", "enabled=1 radius=1 reach=2",
                       "enabled=1 radius=1 reach=6 junk", "enabled=1 radius=1 reach=6\n" + " " * 127,
                       "", "enabled=1 radius=1", "enabled=1 radius=1 reach=6\0extra",
                       "\ufeffenabled=1 radius=1 reach=6"]:
            with self.subTest(config=config):
                h = NativeHarness(self.raw, config); h.run("range")
                r, reach, broad = h.settings()
                self.assertAlmostEqual(r, 0.1); self.assertEqual((reach, broad), (3, 1))
                self.assertEqual(h.handles, {})

    def test_runtime_is_position_independent_under_aslr(self):
        h = NativeHarness(self.raw, "enabled=1 radius=1.5 reach=8", slide=0x28000000)
        h.run("range")
        self.assertEqual(h.settings(), (1.5, 8, 1.5))
        self.assertEqual(h.run("radius"), 1.5)

    def test_contended_reload_returns_without_spinning(self):
        h = NativeHarness(self.raw, "enabled=1 radius=1.5 reach=8")
        h.uc.mem_write(h.state + 24, struct.pack("<I", 1))
        h.run("range")
        self.assertEqual(h.calls, [])
        self.assertEqual(struct.unpack("<I", bytes(h.uc.mem_read(h.state + 24, 4)))[0], 1)

    def test_original_shadow_and_aslr_metadata_remain_valid(self):
        import lief
        h = NativeHarness(self.raw)
        before, after = lief.MachO.parse(list(self.raw)).at(0), lief.MachO.parse(list(h.patched)).at(0)
        self.assertEqual(list(before.function_starts.functions), list(after.function_starts.functions))
        self.assertEqual({(x.address, x.symbol.name) for x in before.bindings},
                         {(x.address, x.symbol.name) for x in after.bindings})
        self.assertEqual({x.address for x in before.relocations}, {x.address for x in after.relocations})
        for s in before.sections:
            if s.name not in ["__text", "__const"]:
                corresponding = next(x for x in after.sections if x.name == s.name and x.segment_name == s.segment_name)
                self.assertEqual(bytes(s.content), bytes(corresponding.content))

    def test_unrecognized_binary_fails_before_patching(self):
        altered = bytearray(self.raw); altered[0x1247D8] ^= 1
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            build.patch_executable(altered, PROFILE, (ROOT / "hitbox.cfg").read_text())

    def test_only_guarded_instructions_change_in_original_code(self):
        h = NativeHarness(self.raw)
        before, after = build.MachO(self.raw), build.MachO(h.patched)
        text = next(s for s in before.sections if s['name'] == '__text')
        allowed = set()
        for hook in PROFILE['hook_sites'].values():
            start = int(hook['address'], 0)
            allowed.update(range(start, start + len(bytes.fromhex(hook['expected']))))
        a, b = before.read(text['va'], text['size']), after.read(text['va'], text['size'])
        differences = {text['va'] + n for n, (x, y) in enumerate(zip(a, b)) if x != y}
        self.assertTrue(differences)
        self.assertTrue(differences <= allowed)

    def test_player_vtable_changes_keep_nonplayers_and_shadow_untouched(self):
        h = NativeHarness(self.raw)
        before, after = build.MachO(self.raw), build.MachO(h.patched)
        selected = {int(t, 0) + int(PROFILE['pick_slot'], 0) for t in PROFILE['player_vtables']}
        original = int(PROFILE['pick_radius_function'], 0)
        native = int(h.report['helpers']['radius']['address'], 0)
        unmodified = 0
        for section in before.sections:
            if section['segment'] != '__DATA' or section['name'] != '__const': continue
            data = before.read(section['va'], section['size'])
            for n in range(0, len(data)-7, 8):
                pointer = struct.unpack_from('<Q', data, n)[0]
                if pointer != original: continue
                address = section['va'] + n
                self.assertEqual(struct.unpack('<Q', after.read(address, 8))[0],
                                 native if address in selected else original)
                if address not in selected: unmodified += 1
        self.assertGreater(unmodified, 20)


class ConfigTests(unittest.TestCase):
    def test_config_bounds_and_format(self):
        self.assertEqual(build.parse_config("enabled=1 radius=0.1 reach=3", PROFILE),
                         "enabled=1\nradius=0.1\nreach=3\n")
        for text in ["enabled=1 radius=nan reach=6", "enabled=1 radius=8.1 reach=6", "enabled=1 radius=1 reach=100"]:
            with self.assertRaises(ValueError): build.parse_config(text, PROFILE)


if __name__ == "__main__":
    unittest.main()
