"""Shared flat filesystem layout for raw, pinned and signed evidence."""
from pathlib import Path


def regular_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('non-regular evidence entry; expected regular file')
    return path


def evidence_files(root):
    root = Path(root)
    evidence = root / 'evidence'
    if root.is_symlink() or not root.is_dir() or evidence.is_symlink() or not evidence.is_dir():
        raise ValueError('invalid audit directory')
    return {path.name: regular_file(path) for path in sorted(evidence.iterdir())}
