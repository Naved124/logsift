"""Log parsers. Each one turns a file into a list of Event objects."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Iterator


def read_lines(path: str | Path) -> Iterator[str]:
    """Yield lines from a plain or gzip-compressed text file (rotated logs are often .gz)."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.strip():
                yield line


def read_text(path: str | Path) -> str:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return handle.read()
