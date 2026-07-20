#!/usr/bin/env python3
"""
anti-anti-frida.py - Binary post-process for Frida server/agent.
Applies .rodata reverse storage and symbol renaming via LIEF.
"""

import sys
import os
import lief
import subprocess
import shutil

def xor_encode(s, key=0x55):
    return ''.join(chr(ord(c) ^ key) for c in s)

def obfuscate_strings(binary, targets):
    for section in binary.sections:
        if section.name != ".rodata":
            continue
        for target in targets:
            addrs = section.search_all(target)
            if not addrs:
                continue
            print(f"  [RODATA] Found '{target}' at {len(addrs)} location(s)")
            patch = [ord(c) for c in target[::-1]]
            for addr in addrs:
                binary.patch_address(section.file_offset + addr, patch)

def rename_symbols(binary):
    changed = []
    for symbol in list(binary.symbols):
        name = symbol.name
        if "frida" in name.lower():
            new_name = name.replace("frida", "ggbond").replace("FRIDA", "RUSBOND")
            if new_name != name:
                try:
                    symbol.name = new_name
                    changed.append((name, new_name))
                except Exception as e:
                    print(f"  [SYM] Failed to rename '{name}': {e}")
    if changed:
        print(f"  [SYM] Renamed {len(changed)} symbol(s)")
        for old, new in changed[:5]:
            print(f"       {old} -> {new}")
        if len(changed) > 5:
            print(f"       ... and {len(changed)-5} more")

def patch_binary(path):
    if not os.path.exists(path):
        print(f"[SKIP] File not found: {path}")
        return
    print(f"\n[PATCH] {path}")
    try:
        binary = lief.parse(path)
        if binary is None:
            print(f"  [ERROR] LIEF failed to parse: {path}")
            return
    except Exception as e:
        print(f"  [ERROR] Cannot parse {path}: {e}")
        return

    obfuscate_strings(binary, ["FridaScriptEngine", "GumScript", "GDBusProxy", "GLib-GIO"])
    rename_symbols(binary)

    try:
        binary.write(path)
        print(f"  [OK] Written patched binary")
    except Exception as e:
        print(f"  [ERROR] Failed to write: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: anti-anti-frida.py <file1> [file2 ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        patch_binary(path)

    print("\n[SUMMARY] Anti-anti-Frida patch complete.")
    print("Reminder: Re-run verify-patch.py to confirm strings are neutralized.")

if __name__ == "__main__":
    main()
