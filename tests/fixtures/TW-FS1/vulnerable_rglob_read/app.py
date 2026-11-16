from pathlib import Path


def load_documents(root):
    for p in Path(root).rglob("*.txt"):
        yield p.read_text()
