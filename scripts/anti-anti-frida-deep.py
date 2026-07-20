#!/usr/bin/env python3
"""
anti-anti-frida-deep.py - Deep binary post-process for Frida server/agent.
Covers: symbol table, .rodata/.data/.dynstr, ELF SONAME, Build ID,
        and sed byte-level replacements for thread/path names.
"""

import sys
import os
import re
import subprocess
import lief
import struct
import hashlib
import random

PREFIX = "ggbond"

# ---------------------------------------------------------------------------
# Byte-level sed replacements (exact-length replacements for thread/path names)
# ---------------------------------------------------------------------------
BYTE_REPLACEMENTS = [
    # thread / process names
    (b"gum-js-loop", b"ggbond-js"),
    (b"pool-frida", b"pool-ggbond"),
    (b"gmain", b"ggmain"),
    (b"gdbus", b"ggdbus"),
    (b"linjector-", b"ggbondinjector-"),
    # path patterns
    (b"/tmp/frida", b"/tmp/ggbond"),
    (b"frida-server", b"ggbond-server"),
    (b"frida-agent", b"ggbond-agent"),
    # misc
    (b"frida:rpc", b"ggbond:rpc"),
    (b"re.frida.", b"re.ggbond."),
]

# ---------------------------------------------------------------------------
# LIEF: symbol + section + string replacements
# ---------------------------------------------------------------------------
FORBIDDEN_SYMBOL_SUBSTRINGS = ["frida", "FRIDA", "Frida"]
FORBIDDEN_STRINGS_LIEF = [
    "FridaScriptEngine", "GumScript", "GDBusProxy",
    "GLib-GIO", "gum-dbus", "gum-subprocess",
    "frida-generate-certificate", "frida-error-quark",
    "libfrida-portal", "libfrida-inject",
    "libfrida-gadget-raw", "libfrida-agent-raw",
]


def replace_in_binary(data, replacements):
    """Apply byte-level replacements."""
    for old, new in replacements:
        if len(old) != len(new):
            print(f"  [BYTE_SKIP] Length mismatch: {old} -> {new}")
            continue
        idx = data.find(old)
        if idx == -1:
            continue
        # Replace all occurrences
        count = data.count(old)
        data = data.replace(old, new)
        print(f"  [BYTE] Replaced {count}x: {old} -> {new}")
    return data


def patch_lief(binary):
    """Patch ELF via LIEF: symbols, SONAME, sections."""
    changed = []

    # 1. Symbol table renaming
    for symbol in list(binary.symbols):
        original_name = symbol.name
        if any(sub in original_name for sub in FORBIDDEN_SYMBOL_SUBSTRINGS):
            new_name = original_name
            for sub in FORBIDDEN_SYMBOL_SUBSTRINGS:
                new_name = new_name.replace(sub, PREFIX)
                new_name = new_name.replace(sub.upper(), PREFIX.upper())
            if new_name != original_name:
                try:
                    symbol.name = new_name
                    changed.append(("SYM", original_name, new_name))
                except Exception as e:
                    print(f"  [SYM_FAIL] {original_name}: {e}")

    # 2. SONAME
    for entry in list(binary.dynamic_entries):
        if entry.tag == lief.ELF.DYNAMIC_TAGS.SONAME:
            old = entry.name
            if any(sub in old for sub in FORBIDDEN_SYMBOL_SUBSTRINGS):
                try:
                    entry.name = re.sub(r'frida', PREFIX, old, flags=re.IGNORECASE)
                    changed.append(("SONAME", old, entry.name))
                except Exception as e:
                    print(f"  [SONAME_FAIL] {old}: {e}")

    # 3. .rodata / .data string obfuscation (reverse)
    for section in binary.sections:
        if section.name not in [".rodata", ".data", ".data.rel.ro", ".dynstr"]:
            continue
        for target in FORBIDDEN_STRINGS_LIEF:
            # Search for target in section content
            content = bytes(section.content)
            idx = content.find(target.encode())
            if idx == -1:
                continue
            # Reverse the string in-place
            patch = [ord(c) for c in target[::-1]]
            offset = section.file_offset + idx
            try:
                binary.patch_address(offset, patch)
                changed.append(("RODATA", section.name, target, target[::-1]))
            except Exception as e:
                print(f"  [RODATA_FAIL] {section.name}+{idx}: {e}")

    return changed


def randomize_build_id(binary):
    """Overwrite .note.gnu.build-id with random bytes."""
    for section in binary.sections:
        if section.name == ".note.gnu.build-id":
            try:
                new_id = bytes(random.randint(0, 255) for _ in range(section.size))
                binary.patch_address(section.file_offset, list(new_id))
                print("  [BUILD_ID] Randomized")
                return True
            except Exception as e:
                print(f"  [BUILD_ID_FAIL] {e}")
    return False


def process_file(path):
    """Apply all patches to a single binary."""
    if not os.path.exists(path):
        print(f"[SKIP] {path}")
        return []

    print(f"\n[PATCH] {path}")
    all_changes = []

    # Step 1: Byte-level replacements
    with open(path, 'rb') as f:
        data = f.read()
    data = replace_in_binary(data, BYTE_REPLACEMENTS)

    # Step 2: LIEF patches
    try:
        binary = lief.parse(path)
        if binary is None:
            print(f"  [ERROR] LIEF parse failed")
            return all_changes

        changes = patch_lief(binary)
        all_changes.extend(changes)

        randomize_build_id(binary)

        # Write back
        binary.write(path)
        print(f"  [LIEF] {len(changes)} changes written.")
    except Exception as e:
        print(f"  [LIEF_ERROR] {e}")

    # Step 3: Write byte-patched data back
    with open(path, 'wb') as f:
        f.write(data)

    # Summary
    if all_changes:
        for change in all_changes[:10]:
            print(f"       {change[0]}: {change[1]} -> {change[2]}")
        if len(all_changes) > 10:
            print(f"       ... +{len(all_changes)-10} more")

    return all_changes


def main():
    if len(sys.argv) < 2:
        print("Usage: anti-anti-frida-deep.py <file1> [file2 ...]")
        sys.exit(1)

    total = 0
    for path in sys.argv[1:]:
        changes = process_file(path)
        total += len(changes)

    print(f"\n[SUMMARY] {total} total patches applied.")
    print("Reminder: Re-run verify-patch-deep.py to confirm.")


if __name__ == "__main__":
    main()
