#!/usr/bin/env python3
"""Fail if public repository files appear to contain proxy credentials."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}
PATTERNS = (
    re.compile(r"(?i)\b(?:ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://"),
    re.compile(r"(?i)https?://\S+[?&](?:token|key|auth|password|secret)=[^\s&]+"),
    re.compile(r"(?i)\b(?:password|passwd|psk|uuid|token|secret)\s*[=:]\s*(?!REPLACE|EXAMPLE|<)[^\s,#]+"),
)


def candidate_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line]


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    for path in candidate_files():
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.append((str(path.relative_to(ROOT)), number, "credential-like value"))

    if findings:
        print("Potential secrets detected; values are intentionally not printed:", file=sys.stderr)
        for filename, number, reason in findings:
            print(f"  - {filename}:{number}: {reason}", file=sys.stderr)
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
