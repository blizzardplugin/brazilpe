#!/usr/bin/env python3
"""Create an unsigned, fingerprint-checked MCPE ARM64 IPA with native config."""
import argparse
import hashlib
import json
import math
import re
import struct
import sys
import zipfile
from pathlib import Path
from string import Template

from keystone import Ks, KsError, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from macho import MachO, insert_segments

ROOT = Path(__file__).resolve().parent
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 20000
CODE_LAYOUT = dict(update=0, range=0x1000, radius=0x1100,
                   cap_s0=0x1200, cap_s1=0x1300, broad=0x1400)
STRINGS_OFFSET = 0x2000
PATH_CAPACITY = 1024
CONFIG_CAPACITY = 127
REQUIRED_IMPORTS = ["time", "getenv", "mkdir", "fopen", "fread", "fclose", "fwrite", "sscanf"]


def parse_config(text, profile):
    if len(text.encode("ascii")) >= CONFIG_CAPACITY:
        raise ValueError("Configuration must contain fewer than 127 ASCII bytes")
    number = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
    match = re.fullmatch(r"enabled=([01])\s+radius=(" + number + r")\s+reach=(" + number + r")\s*", text)
    if not match:
        raise ValueError("Expected exactly enabled=0|1, radius=<number>, reach=<number>")
    enabled, radius, reach = int(match[1]), float(match[2]), float(match[3])
    for name, value in [("radius", radius), ("reach", reach)]:
        if not math.isfinite(value) or not profile[name + "_min"] <= value <= profile[name + "_max"]:
            raise ValueError(f"{name} must be between {profile[name + '_min']} and {profile[name + '_max']}")
    return f"enabled={enabled}\nradius={radius:g}\nreach={reach:g}\n"


def assemble(source, address):
    engine = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoded, _ = engine.asm(source, addr=address, as_bytes=True)
    if encoded is None or not encoded:
        raise ValueError("Assembly produced no instructions")
    return bytes(encoded)


def verify_profile(raw, profile):
    if hashlib.sha256(raw).hexdigest() != profile["executable_sha256"]:
        raise ValueError("Executable fingerprint differs from the inspected 0.15.10 build; no changes applied")
    m = MachO(raw)
    if m.header[1] != profile["cpu_type"]:
        raise ValueError("CPU type does not match profile")
    if next(s["va"] for s in m.segments if s["name"] == "__TEXT") != int(profile["image_base"], 0):
        raise ValueError("Original image base does not match profile")
    if profile["reload_seconds"] != 1:
        raise ValueError("This runtime supports one-second configuration reloads")
    for address_key, bytes_key in [("player_type_function", "player_type_bytes"),
                                   ("pick_radius_function", "pick_radius_bytes"),
                                   ("shadow_radius_function", "shadow_radius_bytes")]:
        expected = bytes.fromhex(profile[bytes_key])
        if m.read(int(profile[address_key], 0), len(expected)) != expected:
            raise ValueError(f"Instruction guard failed: {address_key}")
    rebases = m.rebased_pointers()
    for value in profile["player_vtables"]:
        table = int(value, 0)
        for slot, target in [("pick_slot", "pick_radius_function"),
                             ("type_slot", "player_type_function"),
                             ("shadow_slot", "shadow_radius_function")]:
            pointer_address = table + int(profile[slot], 0)
            pointer = struct.unpack("<Q", m.read(pointer_address, 8))[0]
            if pointer != int(profile[target], 0) or pointer_address not in rebases:
                raise ValueError(f"Vtable/ASLR guard failed at {pointer_address:#x}")
    for name, hook in profile["hook_sites"].items():
        expected = bytes.fromhex(hook["expected"])
        if m.read(int(hook["address"], 0), len(expected)) != expected:
            raise ValueError(f"Hook guard failed: {name}")
    return m


def runtime_segments(macho, profile, defaults):
    link = next(s for s in macho.segments if s["name"] == "__LINKEDIT")
    base, page = link["va"], profile["page_size"]
    state_address = base + page
    addresses = {name: base + off for name, off in CODE_LAYOUT.items()}
    strings = bytearray()
    params = {}

    def pointer(name, value):
        params[name + "_page"] = f"#0x{value & ~4095:x}"
        params[name + "_low"] = f"#{value & 4095}"

    for name, data in [("home", "HOME"), ("suffix", profile["config_path_suffix"]),
                       ("filename", profile["config_filename"]), ("rb", "rb"), ("wb", "wx"),
                       ("format", "enabled=%1d radius=%16f reach=%16f %c"),
                       ("defaults", defaults)]:
        pointer(name, base + STRINGS_OFFSET + len(strings))
        strings.extend(data.encode("ascii") + b"\0")
    if len(strings) > 0x1000:
        raise ValueError("Runtime string table exceeds its section")
    pointer("state", state_address)
    params["home_limit"] = "#" + str(PATH_CAPACITY - len(profile["config_path_suffix"]) - len(profile["config_filename"]) - 1)
    params["defaults_length"] = "#" + str(len(defaults.encode("ascii")))
    for key in ["radius_max", "reach_min", "reach_max"]:
        params[key] = "#" + str(float(profile[key]))
    stubs = macho.import_stubs()
    for name in REQUIRED_IMPORTS:
        if "_" + name not in stubs:
            raise ValueError(f"Required existing import missing: {name}")
        params[name] = f"#0x{stubs['_' + name]:x}"
    update = Template((ROOT / "src/runtime.S.in").read_text()).substitute(params)
    state_ref = f"adrp x8, #0x{state_address & ~4095:x}; add x8, x8, #{state_address & 4095}"
    helpers = {
        "update": update,
        # This bridge replaces an inline v8 assignment, rather than being a C ABI function.
        "range": f"sub sp, sp, #32; str q0, [sp]; str x30, [sp, #16]; bl #0x{addresses['update']:x}; "
                 f"ldr q0, [sp]; ldr x30, [sp, #16]; add sp, sp, #32; mov v8.16b, v0.16b; "
                 f"{state_ref}; ldr s0, [x8, #4]; fmax s8, s8, s0; ret",
        "radius": f"{state_ref}; ldr s0, [x8]; ret",
        "cap_s0": f"{state_ref}; ldr s0, [x8, #4]; ret",
        "cap_s1": f"{state_ref}; ldr s1, [x8, #4]; ret",
        # No stack adjustment: these stores belong to the original pick routine's frame.
        "broad": f"{state_ref}; ldr w8, [x8, #8]; bfi x8, x8, #32, #32; "
                 "str x8, [sp, #0x108]; str w8, [sp, #0x110]; ret",
    }
    code = bytearray(page)
    code[STRINGS_OFFSET:STRINGS_OFFSET + len(strings)] = strings
    lengths = {}
    for name, source in helpers.items():
        encoded = assemble(source, addresses[name])
        limit = 0x1000 if name == "update" else 0x100
        if len(encoded) > limit:
            raise ValueError(f"Native helper exceeds its slot: {name}")
        code[CODE_LAYOUT[name]:CODE_LAYOUT[name] + len(encoded)] = encoded
        lengths[name] = len(encoded)
    state = bytearray(page)
    struct.pack_into("<fff", state, 0, 0.1, 3.0, 1.0)
    struct.pack_into("<f", state, 28, 0.1)
    return bytes(code), bytes(state), addresses, lengths, stubs


def patch_executable(raw, profile, defaults):
    m = verify_profile(raw, profile)
    code, state, addresses, lengths, stubs = runtime_segments(m, profile, defaults)
    out = bytearray(raw)
    changed = []
    for value in profile["player_vtables"]:
        address = int(value, 0) + int(profile["pick_slot"], 0)
        struct.pack_into("<Q", out, m.offset(address, 8), addresses["radius"])
        changed.append(dict(kind="player_pick_pointer", address=hex(address)))
    for name, hook in profile["hook_sites"].items():
        address = int(hook["address"], 0)
        length = len(bytes.fromhex(hook["expected"]))
        source = hook.get("instruction") or f"bl #0x{addresses[hook['helper']]:x}"
        encoded = assemble(source, address)
        if len(encoded) > length:
            raise ValueError(f"Hook exceeds guarded span: {name}")
        encoded += assemble("nop", address) * ((length - len(encoded)) // 4)
        out[m.offset(address, length):m.offset(address, length) + length] = encoded
        changed.append(dict(kind=name, address=hex(address), size=length))
    out = insert_segments(bytes(out), code, state, profile["page_size"])
    updated = MachO(out)
    if any(k == 0x1D for k, _ in updated.commands):
        raise ValueError("Stale main-executable signature is still present")
    shadow = bytes.fromhex(profile["shadow_radius_bytes"])
    if updated.read(int(profile["shadow_radius_function"], 0), len(shadow)) != shadow:
        raise ValueError("Shadow implementation unexpectedly changed")
    if m.rebased_pointers() != updated.rebased_pointers():
        raise ValueError("Original ASLR rebase locations were not preserved")
    if m.import_stubs() != updated.import_stubs():
        raise ValueError("Import stubs changed during segment insertion")
    report = dict(version=profile["version"], cpu="arm64", signature="unsigned",
                  input_executable_sha256=hashlib.sha256(raw).hexdigest(),
                  output_executable_sha256=hashlib.sha256(out).hexdigest(),
                  helpers={n: dict(address=hex(a), size=lengths[n]) for n, a in addresses.items()},
                  hooks=changed, player_vtables=len(profile["player_vtables"]),
                  shadow_code_unchanged=True, original_aslr_locations_preserved=True,
                  runtime_config="Documents/mcpe-hitbox/hitbox.cfg", menu_added=False,
                  physical_ios_test="not performed", server_acceptance="not guaranteed")
    return bytes(out), report, stubs


def build_ipa(source, output, config_path=ROOT / "hitbox.cfg", profile_path=ROOT / "profile.json"):
    import plistlib
    profile = json.loads(Path(profile_path).read_text())
    defaults = parse_config(Path(config_path).read_text(), profile)
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve() or output.exists():
        raise ValueError("Output must be a new file, distinct from the original IPA")
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS or sum(x.file_size for x in members) > MAX_ARCHIVE_BYTES:
            raise ValueError("IPA exceeds bounded inspection limits")
        names = [x.filename for x in members]
        if len(set(names)) != len(names) or any(n.startswith("/") or ".." in Path(n).parts for n in names):
            raise ValueError("Duplicate or unsafe archive paths")
        infos = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info.plist", n)]
        if len(infos) != 1:
            raise ValueError("Expected exactly one top-level iOS application")
        info = plistlib.loads(archive.read(infos[0]))
        if info.get("CFBundleShortVersionString") != profile["version"] or info.get("CFBundleIdentifier") != profile["bundle_id"]:
            raise ValueError("IPA version or bundle identifier does not match profile")
        root = infos[0].rsplit("/", 1)[0] + "/"
        exe = root + info["CFBundleExecutable"]
        patched, report, _ = patch_executable(archive.read(exe), profile, defaults)
        bundled_config = root + "data/mcpe-hitbox/hitbox.cfg"
        if bundled_config in names:
            raise ValueError("Bundled config already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                for member in members:
                    if member.filename.startswith(root + "_CodeSignature/"):
                        continue
                    data = patched if member.filename == exe else archive.read(member)
                    dst.writestr(member, data)
                cfg_info = zipfile.ZipInfo(bundled_config)
                cfg_info.external_attr = 0o100644 << 16
                cfg_info.compress_type = zipfile.ZIP_DEFLATED
                dst.writestr(cfg_info, defaults)
            with zipfile.ZipFile(output) as check:
                if check.testzip() is not None or check.read(exe) != patched:
                    raise ValueError("Output archive validation failed")
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    report["input_ipa_sha256"] = hashlib.file_digest(source.open("rb"), "sha256").hexdigest()
    report["output_ipa_sha256"] = hashlib.file_digest(output.open("rb"), "sha256").hexdigest()
    output.with_suffix(".report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=ROOT / "hitbox.cfg")
    args = parser.parse_args()
    try:
        report = build_ipa(args.ipa, args.output, args.config)
    except (ValueError, OSError, zipfile.BadZipFile, KsError) as error:
        parser.exit(1, f"Build blocked: {error}\n")
    print(f"Unsigned IPA created: {args.output}")
    print(f"Player tables: {report['player_vtables']}; shadow unchanged; physical iOS validation pending")


if __name__ == "__main__":
    main()
