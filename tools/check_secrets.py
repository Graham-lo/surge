#!/usr/bin/env python3
"""Fail if public repository files appear to contain proxy credentials."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}
PUBLIC_SURGE_PROXY_INCLUDES = {
    "surge/profiles/Universal.conf": {"#!include Private-Proxies.dconf"},
    "surge/profiles/iOS.conf": {"#!include Private-Proxies.dconf"},
    "surge/profiles/Private-Proxies.example.dconf": set(),
    "shadowrocket/profiles/Universal.conf": set(),
}
PUBLIC_SURGE_MANAGED_LINES = {
    "surge/profiles/Universal.conf": {
        "#!MANAGED-CONFIG https://raw.githubusercontent.com/Graham-lo/surge/master/"
        "surge/profiles/Universal.conf interval=86400 strict=false"
    },
    "surge/profiles/iOS.conf": {
        "#!MANAGED-CONFIG https://raw.githubusercontent.com/Graham-lo/surge/master/"
        "surge/profiles/iOS.conf interval=86400 strict=false"
    },
    "surge/profiles/Private-Proxies.example.dconf": set(),
    "shadowrocket/profiles/Universal.conf": set(),
}
PUBLIC_SURGE_SAFE_PROXY_LINES = {
    "surge/profiles/Universal.conf": set(),
    "surge/profiles/iOS.conf": set(),
    "surge/profiles/Private-Proxies.example.dconf": {
        "[998][AI][REG][TV] FAIL-CLOSED = socks5, 127.0.0.1, 1, udp-relay=false",
        "[999][APNS] DIRECT = direct",
    },
    "shadowrocket/profiles/Universal.conf": set(),
}
PUBLIC_CLASH_PROXY_ALIASES = {
    "clash-verge/profiles/Universal.yaml": (),
    "clash-verge/profiles/Full.yaml": (
        "- name: '[999][APNS] DIRECT'",
        "type: direct",
        "udp: true",
    ),
}
PROVIDER_EXAMPLE = "clash-verge/profiles/Proxy-Providers.example.yaml"
SECTION_RE = re.compile(r"^\s*\[([^]]+)]\s*$")
PATTERNS = (
    re.compile(r"(?i)\b(?:ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://"),
    re.compile(r"(?i)https?://\S+[?&](?:token|key|auth|password|secret)=[^\s&]+"),
    re.compile(r"(?i)https?://[^/\s:@]+:[^@\s/]+@"),
    re.compile(
        r"(?i)\b(?:password|passwd|passphrase|username|psk|uuid|token|secret|"
        r"api-key|private-key|private_key|client-key|auth-key|authorization|"
        r"ca-passphrase|ca-p12|ca-p12-password|http-api|external-controller-access|"
        r"wifi-access-http-auth)"
        r"\s*[=:]\s*(?!REPLACE|EXAMPLE|<|['\"]{2})[^\s,#]+"
    ),
    re.compile(r"(?i)\bpolicy-path\s*=\s*https?://"),
    re.compile(r"(?i)^\s*#!include\s+https?://"),
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


def line_finding(
    findings: list[tuple[str, int, str]], relative: str, number: int, reason: str
) -> None:
    findings.append((relative, number, reason))


def uncommented_candidate(raw_line: str) -> str | None:
    """Remove one or more ordinary comment prefixes, preserving Surge directives."""
    candidate = raw_line.lstrip()
    commented = False
    while candidate:
        if candidate.startswith("#!"):
            break
        if candidate.startswith("//"):
            candidate = candidate[2:].lstrip()
            commented = True
        elif candidate.startswith(("#", ";")):
            candidate = candidate[1:].lstrip()
            commented = True
        else:
            break
    return candidate if commented else None


def check_commented_clash_line(
    findings: list[tuple[str, int, str]], relative: str, number: int, raw_line: str
) -> None:
    candidate = uncommented_candidate(raw_line)
    if not candidate:
        return
    if re.search(r"(?i)\burl\s*:\s*https?://", candidate):
        line_finding(findings, relative, number, "commented public provider URL")
    if re.search(
        r"(?i)(?:^|[{,\s])(?:proxies|proxy-providers|server|port|uuid|password)\s*:",
        candidate,
    ):
        line_finding(findings, relative, number, "commented public proxy field")


def check_public_surge_profiles(
    findings: list[tuple[str, int, str]],
) -> None:
    """Public Surge-style profiles may use only allowlisted detached/safety policies."""
    for relative, allowed_includes in PUBLIC_SURGE_PROXY_INCLUDES.items():
        path = ROOT / relative
        current: str | None = None
        seen_includes: set[str] = set()
        seen_safe_lines: set[str] = set()
        for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw_line.strip()
            if (
                line.startswith("#!MANAGED-CONFIG")
                and line not in PUBLIC_SURGE_MANAGED_LINES[relative]
            ):
                line_finding(findings, relative, number, "unapproved managed-config URL")
            section_match = SECTION_RE.fullmatch(raw_line)
            if section_match:
                current = section_match.group(1)
                continue
            if current != "Proxy":
                continue
            if line.startswith("#!include"):
                seen_includes.add(line)
                if line not in allowed_includes:
                    line_finding(findings, relative, number, "unapproved public proxy include")
                continue
            if not line:
                continue
            if line.startswith(("#", ";", "//")):
                candidate = re.sub(r"^(?:#+|;+|//+)\s*", "", line)
                if "=" in candidate:
                    right = candidate.split("=", 1)[1].strip()
                    placeholder = "<protocol>, <host>, <port>, <private parameters>"
                    if right != placeholder:
                        line_finding(
                            findings, relative, number, "commented public proxy definition"
                        )
                continue
            if line in PUBLIC_SURGE_SAFE_PROXY_LINES[relative]:
                seen_safe_lines.add(line)
                continue
            line_finding(findings, relative, number, "active public proxy definition")
        if seen_includes != allowed_includes:
            line_finding(findings, relative, 1, "public proxy includes differ from allowlist")
        if seen_safe_lines != PUBLIC_SURGE_SAFE_PROXY_LINES[relative]:
            line_finding(findings, relative, 1, "safe public proxy aliases differ from allowlist")


def check_public_clash_profiles(
    findings: list[tuple[str, int, str]],
) -> None:
    """Public Mihomo profiles may contain only node-free direct aliases."""
    for relative, allowed_proxy_lines in PUBLIC_CLASH_PROXY_ALIASES.items():
        lines = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        for number, raw_line in enumerate(lines, 1):
            check_commented_clash_line(findings, relative, number, raw_line)
        provider_keys = [
            (number, line)
            for number, line in enumerate(lines, 1)
            if re.match(r"^(?:['\"]?proxy-providers['\"]?)\s*:", line)
        ]
        if len(provider_keys) != 1 or not re.fullmatch(
            r"proxy-providers:\s*\{\}\s*", provider_keys[0][1]
        ):
            line_finding(findings, relative, 1, "proxy-providers must be an empty mapping")

        proxy_keys = [
            (number, line)
            for number, line in enumerate(lines, 1)
            if re.match(r"^(?:['\"]?proxies['\"]?)\s*:", line)
        ]
        expected_proxy_keys = 1 if allowed_proxy_lines else 0
        if len(proxy_keys) != expected_proxy_keys or (
            expected_proxy_keys == 1
            and not re.fullmatch(r"proxies\s*:\s*", proxy_keys[0][1])
        ):
            line_finding(findings, relative, 1, "unexpected top-level proxies mapping")

        in_proxies = False
        actual_proxy_lines: list[str] = []
        for number, raw_line in enumerate(lines, 1):
            if raw_line == "proxies:":
                in_proxies = True
                continue
            if in_proxies and raw_line and not raw_line[0].isspace():
                in_proxies = False
            if not in_proxies:
                continue
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            actual_proxy_lines.append(line)
        if tuple(actual_proxy_lines) != allowed_proxy_lines:
            number = proxy_keys[0][0] if proxy_keys else 1
            line_finding(
                findings, relative, number, "public proxy aliases differ from the safe allowlist"
            )


def check_provider_example(
    findings: list[tuple[str, int, str]],
) -> None:
    relative = PROVIDER_EXAMPLE
    path = ROOT / relative
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, raw_line in enumerate(lines, 1):
        check_commented_clash_line(findings, relative, number, raw_line)
    provider_keys = [
        (number, line)
        for number, line in enumerate(lines, 1)
        if re.match(r"^(?:['\"]?proxy-providers['\"]?)\s*:", line)
    ]
    if len(provider_keys) != 1 or not re.fullmatch(
        r"proxy-providers\s*:\s*", provider_keys[0][1]
    ):
        line_finding(findings, relative, 1, "provider example has an unexpected top-level mapping")

    for number, raw_line in enumerate(lines, 1):
        for url in re.findall(r"https?://[^\s'\"},]+", raw_line):
            if url != "http://www.gstatic.com/generate_204":
                line_finding(findings, relative, number, "unexpected URL in provider example")
        # A provider's subscription URL is indented four spaces. Nested
        # health-check URLs are public probes and intentionally allowed.
        match = re.match(r"^ {4}url:\s*(.+?)\s*$", raw_line)
        if not match:
            continue
        value = match.group(1).strip("'\"")
        if value != "REPLACE_WITH_PRIVATE_SUBSCRIPTION_URL":
            line_finding(findings, relative, number, "provider URL is not the exact placeholder")


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
            commented = uncommented_candidate(line)
            if commented and re.match(
                r"(?i)^#!(?:include|MANAGED-CONFIG)\s+https?://", commented
            ):
                findings.append(
                    (str(path.relative_to(ROOT)), number, "commented private directive URL")
                )
            if line.strip().startswith("#!MANAGED-CONFIG"):
                relative = str(path.relative_to(ROOT))
                allowed = PUBLIC_SURGE_MANAGED_LINES.get(relative, set())
                if line.strip() not in allowed:
                    findings.append((relative, number, "unapproved managed-config URL"))

    check_public_surge_profiles(findings)
    check_public_clash_profiles(findings)
    check_provider_example(findings)

    if findings:
        print("Potential secrets detected; values are intentionally not printed:", file=sys.stderr)
        for filename, number, reason in findings:
            print(f"  - {filename}:{number}: {reason}", file=sys.stderr)
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
