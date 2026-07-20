#!/usr/bin/env python3
"""
generate-cross-files.py - Generate Meson cross-compilation files for Frida.
Creates cross files for arm64 and armhf if they don't already exist.
"""

import pathlib
import sys

CROSS_DIR = pathlib.Path("subprojects/frida-core/tools")

CROSS_FILES = {
    "aarch64-linux-gnu": """[binaries]
c = 'aarch64-linux-gnu-gcc'
cpp = 'aarch64-linux-gnu-g++'
ar = 'aarch64-linux-gnu-ar'
strip = 'aarch64-linux-gnu-strip'
pkgconfig = 'pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
""",
    "arm-linux-gnueabihf": """[binaries]
c = 'arm-linux-gnueabihf-gcc'
cpp = 'arm-linux-gnueabihf-g++'
ar = 'arm-linux-gnueabihf-ar'
strip = 'arm-linux-gnueabihf-strip'
pkgconfig = 'pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'arm'
cpu = 'armv7hl'
endian = 'little'
""",
}


def main():
    src_dir = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".")
    cross_path = src_dir / CROSS_DIR
    cross_path.mkdir(parents=True, exist_ok=True)

    for name, content in CROSS_FILES.items():
        fname = f"linux-{name}-cross.txt"
        fpath = cross_path / fname
        if not fpath.exists():
            fpath.write_text(content, encoding="utf-8")
            print(f"[CROSS] Generated: {fpath}")
        else:
            print(f"[CROSS] Exists: {fpath}")


if __name__ == "__main__":
    main()
