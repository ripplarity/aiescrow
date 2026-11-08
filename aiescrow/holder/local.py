"""Folder holder. Interface: put(path), get(name), list()."""

from __future__ import annotations

import shutil
from pathlib import Path


class LocalHolder:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _dest(self, name: str) -> Path:
        d = (self.root / name).resolve()
        if self.root.resolve() not in d.parents:
            raise ValueError(f"path escapes holder: {name}")
        return d

    def put(self, path: Path, name: str | None = None) -> str:
        name = name or Path(path).name
        d = self._dest(name)
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, d)
        return name

    def get(self, name: str) -> bytes:
        return self._dest(name).read_bytes()

    def list(self) -> list[str]:
        return sorted(
            p.relative_to(self.root).as_posix()
            for p in self.root.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(self.root).parts
        )
