"""Git holder: a git repository; every put is a commit (the audit log). No network."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .local import LocalHolder


class GitHolder(LocalHolder):
    def __init__(self, root: Path):
        super().__init__(root)
        if not (self.root / ".git").exists():
            self._git("init", "-q")

    def _git(self, *a: str) -> str:
        r = subprocess.run(
            [
                "git",
                "-c",
                "user.name=aiescrow-holder",
                "-c",
                "user.email=holder@localhost",
                "-c",
                "commit.gpgsign=false",
                *a,
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        )
        return r.stdout

    def put(self, path: Path, name: str | None = None) -> str:
        name = super().put(path, name)
        self._git("add", "--", name)
        self._git("commit", "-q", "--allow-empty", "-m", f"put {name}")
        return name

    def log(self) -> list[str]:
        return self._git("log", "--format=%s").splitlines()
