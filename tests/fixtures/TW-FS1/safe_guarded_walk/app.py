from pathlib import Path


def load_documents(root):
    root = Path(root).resolve()
    for p in root.rglob("*.txt"):
        if p.is_symlink():
            continue
        if not p.resolve().is_relative_to(root):
            continue
        yield p.read_text()
