#!/usr/bin/env python3
"""
verify-patch.py - Verify that anti-anti-frida patches have neutralized key strings.
"""

import sys
import os
import subprocess
import lief

FORBIDDEN_STRINGS = [
    "frida-server",
    "frida-agent",
    "frida_agent_main",
    "re.frida.server",
    "frida:rpc",
    "gum-js-loop",
    "gmain",
    "gdbus",
    "linjector-",
    "pool-frida",
    "FridaScriptEngine",
    "GumScript",
    "GDBusProxy",
]

FORBIDDEN_BYTES = [b"frida", b"FRIDA"]

def check_strings(path):
    """Check for forbidden strings using `strings` and raw scan."""
    issues = []
    # Use strings command if available
    try:
        result = subprocess.run(["strings", path], capture_output=True, text=True)
        lines = result.stdout.lower().splitlines()
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden.lower() in lines or any(forbidden.lower() in l for l in lines):
                issues.append(f"[STRINGS] Found '{forbidden}' in strings output")
    except FileNotFoundError:
        pass

    # Raw binary scan
    with open(path, "rb") as f:
        data = f.read()
    for pattern in FORBIDDEN_BYTES:
        idx = data.find(pattern)
        if idx != -1:
            context = data[max(0, idx-20):idx+20]
            issues.append(f"[RAW] Found {pattern} at 0x{idx:x}: {context}")

    # LIEF .rodata check
    try:
        binary = lief.parse(path)
        if binary:
            for section in binary.sections:
                if section.name == ".rodata":
                    rodata = bytes(section.content)
                    for forbidden in ["FridaScriptEngine", "GumScript", "gum-js-loop"]:
                        if forbidden.encode() in rodata:
                            issues.append(f"[RODATA] Found '{forbidden}' in .rodata")
    except Exception:
        pass

    return issues

def main():
    if len(sys.argv) < 2:
        print("Usage: verify-patch.py <file1> [file2 ...]")
        sys.exit(1)

    all_issues = []
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"[SKIP] {path}")
            continue
        issues = check_strings(path)
        if issues:
            all_issues.extend([(path, i) for i in issues])
        else:
            print(f"[PASS] {path} - no forbidden strings detected")

    if all_issues:
        print("\n[FAIL] Issues found:")
        for path, issue in all_issues:
            print(f"  {path}: {issue}")
        sys.exit(1)
    else:
        print("\n[OK] All files passed verification.")
        sys.exit(0)

if __name__ == "__main__":
    main()
