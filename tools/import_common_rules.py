#!/usr/bin/env python3
"""Optionally refresh repository-owned common rules from their initial source."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from common_rules import (
    COMMON_RULE_PATHS,
    UPSTREAM_API,
    UPSTREAM_RAW,
    UPSTREAM_REPOSITORY,
    license_for,
    upstream_path,
)


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "surge" / "rules" / "common"
LOCK_FILE = ROOT / "common-rules.lock.json"
LOCAL_ADDITIONS_MARKER = "# Graham-maintained additions:"
EOF_MARKER = "################## EOF ##################"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "graham-rules-importer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"unable to fetch {url}: {exc}") from exc


def resolve_commit(ref: str) -> str:
    payload = json.loads(fetch(f"{UPSTREAM_API}/commits/{ref}").decode("utf-8"))
    commit = payload.get("sha", "")
    if not isinstance(commit, str) or len(commit) != 40:
        raise RuntimeError(f"unable to resolve upstream ref: {ref}")
    return commit


def preserve_local_additions(destination: Path, upstream: bytes) -> bytes:
    """Keep the reviewed repository-local block across upstream refreshes."""
    if not destination.is_file():
        return upstream

    current_lines = destination.read_text(encoding="utf-8").splitlines()
    try:
        start = next(
            index
            for index, line in enumerate(current_lines)
            if line.startswith(LOCAL_ADDITIONS_MARKER)
        )
    except StopIteration:
        return upstream

    end = next(
        (
            index
            for index in range(start + 1, len(current_lines))
            if current_lines[index] == EOF_MARKER
        ),
        len(current_lines),
    )
    local_lines = current_lines[start:end]
    upstream_lines = upstream.decode("utf-8").splitlines()
    existing = {line.strip() for line in upstream_lines}
    retained_lines: list[str] = []
    retained_rule_count = 0
    for line in local_lines:
        if line.startswith(("#", ";", "//")):
            retained_lines.append(line)
        elif line and line.strip() not in existing:
            retained_lines.append(line)
            retained_rule_count += 1
    if retained_rule_count == 0:
        return upstream

    insertion = next(
        (index for index, line in enumerate(upstream_lines) if line == EOF_MARKER),
        len(upstream_lines),
    )
    merged = upstream_lines[:insertion] + retained_lines + upstream_lines[insertion:]
    return ("\n".join(merged) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replace local common rules with a reviewed upstream snapshot"
    )
    parser.add_argument("--ref", default="master", help="upstream branch, tag or commit")
    args = parser.parse_args()

    try:
        commit = resolve_commit(args.ref)
        outputs: dict[Path, bytes] = {}
        locked_files: dict[str, object] = {}
        for name in COMMON_RULE_PATHS:
            source = upstream_path(name)
            upstream_content = fetch(f"{UPSTREAM_RAW}/{commit}/{source}")
            upstream_content.decode("utf-8")
            destination = DESTINATION / f"{name}.list"
            content = preserve_local_additions(destination, upstream_content)
            outputs[destination] = content
            locked_files[name] = {
                "license": license_for(name),
                "sha256": hashlib.sha256(upstream_content).hexdigest(),
                "source": source,
                "surge": str(destination.relative_to(ROOT)),
            }
    except (RuntimeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        return 1

    lock = {
        "schema": 1,
        "note": "Static snapshot only; clients use this repository, not the upstream URL.",
        "source_commit": commit,
        "source_repository": UPSTREAM_REPOSITORY,
        "files": locked_files,
    }
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    LOCK_FILE.write_text(
        json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Imported {len(outputs)} static common rules at upstream commit {commit}.")
    print("Review the diff, then run: python3 tools/build_rules.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
