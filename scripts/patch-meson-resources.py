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
            while i < len(lines):
                if lines[i].strip().startswith('backend_sources += [android_data]'):
                    i += 1
                    break
                i += 1
            continue

        # Simplify helper_backend_data: remove native/bpf helper binary inputs and cleanup command args.
        if 'helper_backend_data = custom_target(' in line and 'frida-data-helper-backend' in line:
            out.append(line)
            i += 1
            while i < len(lines):
                if "helpers_native_dir / 'bootstrapper.bin'," in lines[i]:
                    i += 1
                    continue
                if "helpers_native_dir / 'loader.bin'," in lines[i]:
                    i += 1
                    continue
                if "helpers_bpf_noarch_dir  / 'activity-sampler.elf'," in lines[i]:
                    i += 1
                    continue
                if "helpers_bpf_arch_dir  / 'spawn-gater.elf'," in lines[i]:
                    i += 1
                    continue
                if "helpers_bpf_arch_dir  / 'syscall-tracer.elf'," in lines[i]:
                    i += 1
                    continue
                if "'@INPUT1@'," in lines[i] or "'@INPUT2@'," in lines[i] or "'@INPUT3@'," in lines[i] or "'@INPUT4@'," in lines[i] or "'@INPUT5@'," in lines[i]:
                    i += 1
                    continue
                out.append(lines[i])
                i += 1
                if i < len(lines) and lines[i-1].strip().startswith('helper_backend_sources += [helper_backend_data]'):
                    break
            continue

        # Simplify helper_process_data blocks: drop the 4 helper inputs and restore command.
        if 'helper_process_data = custom_target(' in line and 'frida-data-helper-process' in line:
            out.append(line)
            i += 1
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
                # Restore command array if it was simplified to nothing
                if "depends: helper_depends," in lines[i] and i+1 < len(lines) and lines[i+1].strip().startswith(')'):
                    indent = '        '
                    out.append(f"{indent}command: [")
                    out.append(f"{indent}  resource_compiler_cmd_array,")
                    out.append(f"{indent}  '-c', '@INPUT0@',")
                    out.append(f"{indent}  '-o', meson.current_build_dir() / 'frida-data-helper-process',")
                    out.append(f"{indent}],")
                out.append(lines[i])
                i += 1
                if i < len(lines) and lines[i-1].strip().startswith('backend_sources += [helper_process_data]'):
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
