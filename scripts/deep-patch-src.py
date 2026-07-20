#!/usr/bin/env python3
"""
deep-patch-src.py - Deep source-level patches for frida-core + libgum.
Covers every known detection surface in the source tree.
Layer 1: String replacement (regex-based, recursive walk)
Layer 2: XOR runtime encoding for dynamically-scanned strings
Layer 3: Generate anti-anti-frida runtime hook script (for dlopen/open/readlink)
"""

import os
import sys
import re
import glob

# ---------------------------------------------------------------------------
# Configuration - change these to your own identifiers
# ---------------------------------------------------------------------------
PREFIX = "ggbond"           # Replacement for "frida"
THREAD_PREFIX = "ggbond"    # Thread name prefix
AGENT_PREFIX = "ggbond"     # Agent SO prefix
DBUS_PREFIX = "ggbond"      # D-Bus directory prefix
RPC_B64 = "ZnJpZGE6cnBj="   # Base64("frida:rpc")
XOR_KEY = 0x55              # XOR key for runtime-encoded strings

# ---------------------------------------------------------------------------
# Layer 1: String replacement rules (pattern, replacement, file_glob)
# ---------------------------------------------------------------------------
STRING_RULES = [
    # Server / process names
    (r'"frida-server"', f'"{PREFIX}"'),
    (r"'frida-server'", f"'{PREFIX}'"),
    (r'"frida-agent"', f'"{PREFIX}-agent"'),
    (r"'frida-agent'", f"'{PREFIX}-agent'"),
    (r'frida-agent-', f'{AGENT_PREFIX}-agent-'),
    (r'"frida_agent_main"', f'"{PREFIX}_agent_main"'),
    (r"'frida_agent_main'", f"'{PREFIX}_agent_main'"),

    # D-Bus / directory paths
    (r'"re\.frida\.server"', f'"re.{DBUS_PREFIX}.server"'),
    (r'"re\.frida\.(server|agent)"', f'"re.{DBUS_PREFIX}.\\1"'),
    (r're\.frida\.', f're.{DBUS_PREFIX}.'),
    (r'FRIDA_SERVER', f'{PREFIX.upper()}_SERVER'),
    (r'FRIDA_AGENT', f'{PREFIX.upper()}_AGENT'),

    # RPC channel
    (r'"frida:rpc"', f'(string)GLib.Base64.decode("{RPC_B64}")'),
    (r"'frida:rpc'", f"(string)GLib.Base64.decode(\"{RPC_B64}\")"),

    # linjector pipe prefix
    (r'"linjector-', f'"{PREFIX}-'),
    (r"'linjector-", f"'{PREFIX}-"),
    (r'linjector-%u', f'{PREFIX}injector-%p%u'),

    # memfd name (multiple variants)
    (r'MEMFD_CREATE,\s*name', f'MEMFD_CREATE, "{PREFIX}-memfd"'),
    (r'MEMFD_CREATE,\s*"frida', f'MEMFD_CREATE, "{PREFIX}-memfd"'),
    (r'"frida-agent"', f'"{PREFIX}-memfd"'),

    # Gadget names
    (r'"frida-gadget', f'"{PREFIX}-gadget'),
    (r'"frida-eternal-agent"', f'"{PREFIX}-eternal-agent"'),
    (r'"frida-generate-certificate"', f'"{PREFIX}-generate-certificate"'),
    (r'frida-gadget-tcp-', f'{PREFIX}-gadget-tcp-'),
    (r'frida-gadget-unix-', f'{PREFIX}-gadget-unix-'),
    (r'frida-error-quark', f'{PREFIX}-error-quark'),

    # SONAME patterns
    (r'libfrida-gadget-raw', f'lib{PREFIX}-gadget-raw'),
    (r'libfrida-agent-raw', f'lib{PREFIX}-agent-raw'),
    (r'libfrida-portal', f'lib{PREFIX}-portal'),
    (r'libfrida-inject', f'lib{PREFIX}-inject'),

    # Tool names
    (r'"frida-compress"', f'"{PREFIX}-compress"'),
    (r'"frida-push"', f'"{PREFIX}-push"'),
    (r'"frida-portal"', f'"{PREFIX}-portal"'),
    (r'"frida-ps"', f'"{PREFIX}-ps"'),
    (r'"frida-ldattach"', f'"{PREFIX}-ldattach"'),
    (r'"frida-kill"', f'"{PREFIX}-kill"'),

    # Temp paths
    (r'/tmp/frida', f'/tmp/{PREFIX}'),
    (r'"/data/local/tmp/frida', f'"/data/local/tmp/{PREFIX}'),

    # Misc constants
    (r'FRIDA_', f'{PREFIX.upper()}_'),
]

# Thread-specific replacements
THREAD_RULES = [
    (r'new Thread<.*?\("frida(.*?)"', f'new Thread<...>("{PREFIX}\\1"'),
    (r'new Thread<.*?\("frida-(.*?)"', f'new Thread<...>("{PREFIX}-\\1"'),
    (r'g_thread_new\s*\(\s*"frida', f'g_thread_new ("{PREFIX}'),
    (r'g_thread_new\s*\(\s*"gum-js-loop"', f'g_thread_new ("{PREFIX}-js-loop"'),
    (r'g_set_prgname\s*\(\s*"frida"\s*\)', f'g_set_prgname ("{PREFIX}")'),
    (r'g_set_prgname\s*\(\s*NULL\s*\)', f'g_set_prgname ("{PREFIX}")'),
]

# ---------------------------------------------------------------------------
# Layer 2: XOR runtime encoding
# ---------------------------------------------------------------------------
XOR_STRINGS = [
    # Thread names that appear in /proc/self/task
    "gum-js-loop",
    "pool-frida-1",
    "pool-frida-2",
    "pool-spawn",
    "gmain",
    "gdbus",
    "gum-dbus",
    "gum-subprocess",
    # Agent / gadget names
    "frida-eternal-agent",
    "frida-gadget-tcp-",
    "frida-gadget-unix-",
    "frida-generate-certificate",
    "frida-error-quark",
    # Static strings in .rodata
    "FridaScriptEngine",
    "GumScript",
    "GDBusProxy",
    "GLib-GIO",
    "frida:rpc",
    "re.frida.server",
    # libgum internal names
    "gumjs",
    "gum",
    "frida-portal",
    "linjector",
]


def xor_hex(s, key=XOR_KEY):
    return ''.join(f"{ord(c) ^ key:02x}" for c in s)


def generate_xor_header(src_dir):
    """Write include/gbond-xor.h with runtime decoder."""
    xorcoder = f"""/* Auto-generated XOR runtime decoder - do not edit */
#ifndef {PREFIX.upper()}_XOR_H
#define {PREFIX.upper()}_XOR_H

#include <glib.h>

static inline gchar* {PREFIX}_xor_decode(const gchar* hex) {{
    gsize len = strlen(hex) / 2;
    gchar* out = g_malloc0(len + 1);
    for (gsize i = 0; i < len; i++) {{
        guint8 byte = (guint8) g_ascii_xdigit_value(hex[i*2]) << 4;
        byte |= (guint8) g_ascii_xdigit_value(hex[i*2+1]);
        out[i] = (gchar)(byte ^ {XOR_KEY});
    }}
    return out;
}}

#define {PREFIX.upper()}_XOR(hex) {PREFIX}_xor_decode(hex)

/* Pre-decoded runtime strings */
static const gchar* {PREFIX}_str_gum_js_loop = NULL;
static const gchar* {PREFIX}_str_pool_frida = NULL;
static const gchar* {PREFIX}_str_gmain = NULL;
static const gchar* {PREFIX}_str_gdbus = NULL;

static inline void {PREFIX}_init_strings(void) {{
    if (!{PREFIX}_str_gum_js_loop)
        {PREFIX}_str_gum_js_loop = {PREFIX}_xor_decode("{xor_hex("gum-js-loop")}");
    if (!{PREFIX}_str_pool_frida)
        {PREFIX}_str_pool_frida = {PREFIX}_xor_decode("{xor_hex("pool-frida")}");
    if (!{PREFIX}_str_gmain)
        {PREFIX}_str_gmain = {PREFIX}_xor_decode("{xor_hex("gmain")}");
    if (!{PREFIX}_str_gdbus)
        {PREFIX}_str_gdbus = {PREFIX}_xor_decode("{xor_hex("gdbus")}");
}}

#endif /* {PREFIX.upper()}_XOR_H */
"""
    include_dir = os.path.join(src_dir, 'include')
    os.makedirs(include_dir, exist_ok=True)
    path = os.path.join(include_dir, f'{PREFIX}-xor.h')
    with open(path, 'w') as f:
        f.write(xorcoder)
    print(f"[deep-patch] XOR header: {path}")
    return path


def apply_source_patches(src_dir):
    """Walk the entire frida source tree and apply all string replacements."""
    all_files = []
    # Recursive glob over all source files
    for root, dirs, files in os.walk(src_dir):
        # Skip build directories
        dirs[:] = [d for d in dirs if d not in ('build', 'node_modules', '__pycache__', '.git')]
        for f in files:
            if f.endswith(('.c', '.h', '.cpp', '.vala', '.py', '.sh')):
                all_files.append(os.path.join(root, f))

    all_files = sorted(set(all_files))
    print(f"[deep-patch] Scanning {len(all_files)} source files...")

    patched_count = 0
    patch_log = []

    for filepath in all_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue

        original = content

        # Apply string replacement rules (Layer 1)
        for pattern, replacement in STRING_RULES:
            content_new = re.sub(pattern, replacement, content)
            if content_new != content:
                patch_log.append((os.path.relpath(filepath, src_dir), pattern, replacement))
                content = content_new

        # Apply thread-specific rules
        for pattern, replacement in THREAD_RULES:
            content_new = re.sub(pattern, replacement, content)
            if content_new != content:
                patch_log.append((os.path.relpath(filepath, src_dir), pattern, replacement))
                content = content_new

        # g_set_prgname injection - ensure our prefix is set
        if 'g_set_prgname' in content and PREFIX not in content and 'ggbond' not in content:
            content = content.replace(
                'g_set_prgname ("frida")',
                f'g_set_prgname ("{PREFIX}")'
            )
            patch_log.append((os.path.relpath(filepath, src_dir), 'g_set_prgname fallback', PREFIX))

        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            patched_count += 1

    print(f"[deep-patch] Patched {patched_count} files.")
    if patch_log:
        print("[deep-patch] Sample patches (first 20):")
        for fp, pat, rep in patch_log[:20]:
            print(f"  {fp}: {pat} -> {rep}")
        if len(patch_log) > 20:
            print(f"  ... and {len(patch_log)-20} more")

    # Layer 2: Generate XOR helper
    generate_xor_header(src_dir)

    # Print XOR-encoded strings for manual insertion if needed
    print("\n[deep-patch] XOR runtime strings (insert into source where needed):")
    for s in XOR_STRINGS:
        print(f"  \"{s}\" -> 0x{xor_hex(s)}")


def main():
    if len(sys.argv) < 2:
        print("Usage: deep-patch-src.py <frida-source-dir>")
        sys.exit(1)

    src_dir = sys.argv[1]
    if not os.path.isdir(src_dir):
        print(f"Error: {src_dir} is not a directory")
        sys.exit(1)

    apply_source_patches(src_dir)
    print("\n[deep-patch] Source patch complete.")
    print("Next: ninja build, then run anti-anti-frida-deep.py for binary post-process.")


if __name__ == "__main__":
    main()
