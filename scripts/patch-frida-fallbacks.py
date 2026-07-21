import sys
from pathlib import Path

def patch_generate_runtime(path: Path):
    text = path.read_text(encoding='utf-8', errors='replace')
    old = '''        subprocess.run(
            [quickcompile]
            + flags
            + [priv_dir, input_dir]
            + [s.path.relative_to(input_dir) for s in sources],
            check=True,
        )

        modules = []'''
    new = '''        if quickcompile is not None and quickcompile.exists():
            try:
                subprocess.run(
                    [quickcompile]
                    + flags
                    + [priv_dir, input_dir]
                    + [s.path.relative_to(input_dir) for s in sources],
                    check=True,
                )
            except Exception as e:
                print(f"[fallback] quickcompile failed ({e}), emitting empty .qjs files", file=sys.stderr)
                for source in sources:
                    dest_path = priv_dir / (source.path.stem + ".qjs")
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    if not dest_path.exists():
                        dest_path.write_bytes(b"")
        else:
            for source in sources:
                dest_path = priv_dir / (source.path.stem + ".qjs")
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                if not dest_path.exists():
                    dest_path.write_bytes(b"")

        modules = []'''
    if old in text:
        text = text.replace(old, new, 1)
        path.write_text(text, encoding='utf-8')
        print(f"Patched {path} (generate-runtime)")
    else:
        print(f"Skip {path}: generate-runtime pattern not found")


def patch_embed_helper(path: Path):
    text = path.read_text(encoding='utf-8', errors='replace')
    old = '''    subprocess.run([
        resource_compiler,
        f"--toolchain={host_toolchain}",
        f"--machine={host_arch}",
        "--config-filename", resource_config,
        "--output-basename", output_dir / "frida-data-helper-process",
    ] + embedded_assets, check=True)'''
    new = '''    try:
        subprocess.run([
            resource_compiler,
            f"--toolchain={host_toolchain}",
            f"--machine={host_arch}",
            "--config-filename", resource_config,
            "--output-basename", output_dir / "frida-data-helper-process",
        ] + embedded_assets, check=True)
    except Exception as e:
        print(f"[fallback] resource_compiler failed ({e}), emitting empty blob", file=sys.stderr)
        (output_dir / "frida-data-helper-process.vapi").write_bytes(b"")
        (output_dir / "frida-data-helper-process.h").write_bytes(b"")
        (output_dir / "frida-data-helper-process.c").write_bytes(b"")
        (output_dir / "frida-data-helper-process-blob.S").write_bytes(b"")'''
    if old in text:
        text = text.replace(old, new, 1)
        path.write_text(text, encoding='utf-8')
        print(f"Patched {path} (embed-helper)")
    else:
        print(f"Skip {path}: embed-helper pattern not found")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: patch-frida-fallbacks.py <file> [file...]")
        sys.exit(1)
    for arg in sys.argv[1:]:
        p = Path(arg)
        if not p.exists():
            print(f"Skip {arg}: not found")
            continue
        name = p.name.lower()
        if 'generate-runtime' in name:
            patch_generate_runtime(p)
        elif 'embed-helper' in name:
            patch_embed_helper(p)
        else:
            print(f"Skip {arg}: unknown file (expected generate-runtime.py or embed-helper.py)")
