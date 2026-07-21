from pathlib import Path
import sys


def patch_meson_build(path: Path):
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    out = []
    i = 0
    removed_android = False
    while i < len(lines):
        line = lines[i]
        # Remove the android_data custom_target block entirely.
        if not removed_android and "android_data = custom_target('frida-data-android'" in line:
            removed_android = True
            # Skip until we find a line that is not part of the block.
            while i < len(lines):
                if lines[i].strip().startswith('backend_sources += [android_data]'):
                    i += 1
                    break
                i += 1
            continue

        # Simplify helper_process_data blocks: drop the 4 helper inputs.
        if 'helper_process_data = custom_target(' in line and 'frida-data-helper-process' in line:
            out.append(line)
            i += 1
            # Consume until output/command block ends.
            while i < len(lines):
                if "helper_modern," in lines[i]:
                    i += 1
                    continue
                if "helper_legacy," in lines[i]:
                    i += 1
                    continue
                if "helper_emulated_modern," in lines[i]:
                    i += 1
                    continue
                if "helper_emulated_legacy," in lines[i]:
                    i += 1
                    continue
                if "'@INPUT1@'," in lines[i] or "'@INPUT2@'," in lines[i] or "'@INPUT3@'," in lines[i] or "'@INPUT4@'," in lines[i]:
                    i += 1
                    continue
                out.append(lines[i])
                i += 1
                if lines[i-1].strip().startswith('backend_sources += [helper_process_data]'):
                    break
            continue

        out.append(line)
        i += 1

    path.write_text('\n'.join(out), encoding='utf-8')
    print(f"Patched {path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: patch-meson-resources.py <meson.build>")
        sys.exit(1)
    patch_meson_build(Path(sys.argv[1]))
