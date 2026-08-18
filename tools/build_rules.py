#!/usr/bin/env python3
"""Validate canonical Surge rules and build client-specific mirrors."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

from common_rules import COMMON_RULE_PATHS, license_for


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "surge" / "rules"
LEGACY_DIR = ROOT / "rules"
SHADOWROCKET_DIR = ROOT / "shadowrocket" / "rules"
CLASH_VERGE_DIR = ROOT / "clash-verge" / "rules"
MANIFEST = ROOT / "rules-manifest.json"

RULE_NAMES = (
    "AI",
    "APNs",
    "Binance",
    "BinanceDirect",
    "Bybit",
    "BybitDirect",
    "Claude",
    "OKX",
    "OKXDirect",
    "OpenAI",
)
ALLOWED_TYPES = {
    "AND",
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX",
    "DOMAIN-WILDCARD",
    "IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "URL-REGEX",
    "USER-AGENT",
}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}


class RuleError(ValueError):
    pass


def source_text(relative_name: str) -> str:
    path = SOURCE_DIR / f"{relative_name}.list"
    if not path.is_file():
        raise RuleError(f"missing canonical ruleset: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def rules_from(text: str, source: str) -> list[str]:
    rules: list[str] = []
    seen: set[str] = set()

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue

        rule_type = line.split(",", 1)[0].upper()
        if rule_type not in ALLOWED_TYPES:
            raise RuleError(f"{source}:{number}: unsupported rule type {rule_type}")
        if line in seen:
            raise RuleError(f"{source}:{number}: duplicate rule")

        parts = [part.strip() for part in line.split(",")]
        if rule_type in DOMAIN_TYPES | {"DOMAIN-KEYWORD"} and len(parts) != 2:
            raise RuleError(f"{source}:{number}: unexpected policy or parameter")
        if rule_type == "IP-ASN" and (
            len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] != "no-resolve")
        ):
            raise RuleError(f"{source}:{number}: invalid IP-ASN parameters")
        if rule_type in DOMAIN_TYPES and not re.fullmatch(r"[A-Za-z0-9*?_.-]+", parts[1]):
            raise RuleError(f"{source}:{number}: invalid domain value")
        if rule_type in {"PROCESS-NAME", "URL-REGEX", "USER-AGENT"} and len(parts) != 2:
            raise RuleError(f"{source}:{number}: invalid {rule_type} parameters")
        if rule_type in {"IP-CIDR", "IP-CIDR6"}:
            if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] != "no-resolve"):
                raise RuleError(f"{source}:{number}: invalid IP rule parameters")
            try:
                network = ipaddress.ip_network(parts[1], strict=False)
            except ValueError as exc:
                raise RuleError(f"{source}:{number}: invalid CIDR") from exc
            expected = 6 if rule_type == "IP-CIDR6" else 4
            if network.version != expected:
                raise RuleError(f"{source}:{number}: address family does not match {rule_type}")

        seen.add(line)
        rules.append(line)

    if not rules:
        raise RuleError(f"{source}: ruleset is empty")
    return rules


def render_shadowrocket(name: str, rules: list[str], source: str) -> str:
    compatible = [rule for rule in rules if "PROCESS-NAME" not in rule]
    omitted = len(rules) - len(compatible)
    lines = [
        f"# NAME: {name}",
        f"# GENERATED: tools/build_rules.py from {source}",
        "# FORMAT: Shadowrocket RULE-SET (policy omitted)",
    ]
    if omitted:
        lines.append(f"# OMITTED: {omitted} desktop process-scoped rule(s)")
    lines.extend(("", *compatible, ""))
    return "\n".join(lines)


def render_clash(name: str, rules: list[str], source: str) -> str:
    unsupported = ("USER-AGENT,", "URL-REGEX,")
    compatible = [rule for rule in rules if not rule.startswith(unsupported)]
    omitted = len(rules) - len(compatible)
    lines = [
        f"# NAME: {name}",
        f"# GENERATED: tools/build_rules.py from {source}",
        "# FORMAT: Mihomo/Clash Verge classical rule-provider",
    ]
    if omitted:
        lines.append(f"# OMITTED: {omitted} unsupported URL/User-Agent rule(s)")
    lines.append("payload:")
    for rule in compatible:
        adapted = rule.replace(
            "(PROCESS-NAME,Claude*)", "(PROCESS-NAME-REGEX,(?i)^Claude.*)"
        )
        lines.append("  - '" + adapted.replace("'", "''") + "'")
    lines.append("")
    return "\n".join(lines)


def expected_outputs() -> tuple[dict[Path, str], dict[str, object]]:
    outputs: dict[Path, str] = {}
    manifest_rules: dict[str, object] = {}

    for name in RULE_NAMES:
        canonical = source_text(name)
        rules = rules_from(canonical, f"surge/rules/{name}.list")
        outputs[LEGACY_DIR / f"{name}.list"] = canonical
        source = f"surge/rules/{name}.list"
        outputs[SHADOWROCKET_DIR / f"{name}.list"] = render_shadowrocket(name, rules, source)
        outputs[CLASH_VERGE_DIR / f"{name}.yaml"] = render_clash(name, rules, source)
        manifest_rules[name] = {
            "rule_count": len(rules),
            "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "surge": f"surge/rules/{name}.list",
            "shadowrocket": f"shadowrocket/rules/{name}.list",
            "clash_verge": f"clash-verge/rules/{name}.yaml",
            "legacy_surge": f"rules/{name}.list",
        }

    manifest_common: dict[str, object] = {}
    for name in COMMON_RULE_PATHS:
        canonical = source_text(f"common/{name}")
        source = f"surge/rules/common/{name}.list"
        rules = rules_from(canonical, source)
        display_name = f"common/{name}"
        outputs[SHADOWROCKET_DIR / "common" / f"{name}.list"] = render_shadowrocket(
            display_name, rules, source
        )
        outputs[CLASH_VERGE_DIR / "common" / f"{name}.yaml"] = render_clash(
            display_name, rules, source
        )
        manifest_common[name] = {
            "license": license_for(name),
            "rule_count": len(rules),
            "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "surge": source,
            "shadowrocket": f"shadowrocket/rules/common/{name}.list",
            "clash_verge": f"clash-verge/rules/common/{name}.yaml",
        }

    manifest = {
        "schema": 1,
        "source_of_truth": "surge/rules",
        "generated_by": "tools/build_rules.py",
        "rules": manifest_rules,
        "common_rules": manifest_common,
    }
    outputs[MANIFEST] = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return outputs, manifest


def check(outputs: dict[Path, str]) -> int:
    stale: list[str] = []
    for path, expected in outputs.items():
        actual = path.read_text(encoding="utf-8") if path.is_file() else None
        if actual != expected:
            stale.append(str(path.relative_to(ROOT)))
    if stale:
        print("Generated files are missing or stale:", file=sys.stderr)
        for path in stale:
            print(f"  - {path}", file=sys.stderr)
        print("Run: python3 tools/build_rules.py", file=sys.stderr)
        return 1
    print(
        f"Validated {len(RULE_NAMES)} maintained and {len(COMMON_RULE_PATHS)} "
        "common rulesets with all generated mirrors."
    )
    return 0


def write(outputs: dict[Path, str]) -> None:
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(
        f"Built {len(RULE_NAMES)} maintained and {len(COMMON_RULE_PATHS)} common "
        "rulesets for Surge, Shadowrocket and Clash Verge."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when generated files differ")
    args = parser.parse_args()
    try:
        outputs, _ = expected_outputs()
    except RuleError as exc:
        print(f"Rule validation failed: {exc}", file=sys.stderr)
        return 1
    if args.check:
        return check(outputs)
    write(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
