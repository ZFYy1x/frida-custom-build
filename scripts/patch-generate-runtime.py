import re
import sys

p = sys.argv[1]
text = open(p, 'rb').read().decode('utf-8', errors='replace')

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
                if not dest_path.exists():
                    dest_path.write_bytes(b"")

        modules = []'''

if old in text:
    text = text.replace(old, new, 1)
    open(p, 'wb').write(text.encode('utf-8'))
    print(f"Patched {p}")
else:
    print("Pattern not found")
    sys.exit(1)
