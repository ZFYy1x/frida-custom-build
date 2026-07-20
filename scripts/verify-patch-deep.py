#!/usr/bin/env python3
"""
verify-patch-deep.py - Verify deep anti-anti-frida patches.
Checks binary data, LIEF sections, symbol table, and byte-level patterns.
"""

import sys
import os
import subprocess
import lief
import struct

PREFIX = "ggbond"

FORBIDDEN_RAW_BYTES = [
    b"frida-server",
    b"frida-agent",
    b"frida_agent_main",
    b"re.frida.server",
    b"frida:rpc",
    b"gum-js-loop",
    b"pool-frida",
    b"linjector-",
    b"libfrida-",
    b"frida-generate-certificate",
    b"frida-error-quark",
    b"frida-eternal-agent",
    b"frida-gadget-tcp-",
    b"frida-gadget-unix-",
]

FORBIDDEN_STRINGS_LIEF = [
    "FridaScriptEngine", "GumScript", "GDBusProxy",
    "GLib-GIO", "gum-dbus", "gum-subprocess",
]

FORBIDDEN_SYMBOL_SUBSTR = ["frida", "FRIDA"]


def check_raw(data, path):
    issues = []
    for pattern in FORBIDDEN_RAW_BYTES:
        idx = data.find(pattern)
        if idx != -1:
            context = data[max(0, idx-20):idx+len(pattern)+20]
            issues.append(f"[RAW] Found '{pattern}' at 0x{idx:x}: {context}")
    return issues


def check_lief(binary, path):
    issues = []
    # SONAME
    for entry in binary.dynamic_entries:
        if entry.tag == lief.ELF.DYNAMIC_TAGS.SONAME:
            if any(sub in entry.name for sub in FORBIDDEN_SYMBOL_SUBSTR):
                issues.append(f"[SONAME] {entry.name}")

    # .rodata/.data strings
    for section in binary.sections:
        if section.name not in [".rodata", ".data", ".dynstr"]:
            continue
        content = bytes(section.content)
        for target in FORBIDDEN_STRINGS_LIEF:
            if target.encode() in content:
                issues.append(f"[SECTION.{section.name}] Found '{target}'")

    # Symbols
    for symbol in binary.symbols:
        if any(sub in symbol.name for sub in FORBIDDEN_SYMBOL_SUBSTR):
            issues.append(f"[SYMBOL] '{symbol.name}' still contains forbidden substring")

    return issues


def check_strings_cmd(path):
    issues = []
    try:
        result = subprocess.run(["strings", path], capture_output=True, text=True)
        output = result.stdout
        for forbidden in ["frida-server", "frida-agent", "gum-js-loop", "pool-frida", "gmain"]:
            if forbidden.lower() in output.lower():
                issues.append(f"[STRINGS] '{forbidden}' visible in strings output")
    except FileNotFoundError:
        pass
    return issues


def main():
    if len(sys.argv) < 2:
        print("Usage: verify-patch-deep.py <file1> [file2 ...]")
        sys.exit(1)

    all_issues = []
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"[SKIP] {path}")
            continue

        with open(path, 'rb') as f:
            data = f.read()

        issues = []
        issues += check_raw(data, path)
        issues += check_strings_cmd(path)

        try:
            binary = lief.parse(path)
            if binary:
                issues += check_lief(binary, path)
        except Exception as e:
            print(f"[LIEF_ERROR] {path}: {e}")

        if issues:
            all_issues.extend([(path, i) for i in issues])
        else:
            print(f"[PASS] {path}")

    if all_issues:
        print("\n[FAIL] Issues found:")
        for path, issue in all_issues:
            print(f"  {path}: {issue}")
        sys.exit(1)
    else:
        print("\n[OK] All files passed deep verification.")
        sys.exit(0)


if __name__ == "__main__":
    main()
