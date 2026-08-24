#!/usr/bin/env python3
"""Audit cross-policy overlaps and enforce first-match order in public profiles."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "conflict-baseline.json"

# Order is intentional and mirrors every public profile. Earlier rules win.
RULESETS = (
    ("BinanceDirect", "DIRECT"),
    ("Binance", "BIN"),
    ("BybitDirect", "DIRECT"),
    ("Bybit", "BYB"),
    ("OKXDirect", "DIRECT"),
    ("OKX", "OKX"),
    ("common/non_ip/lan", "DIRECT"),
    ("OpenAI", "AI"),
    ("common/ip/lan", "DIRECT"),
    ("APNs", "APNS"),
    ("Claude", "AI"),
    ("AI", "AI"),
    ("common/non_ip/ai", "AI"),
    ("common/non_ip/apple_intelligence", "AI"),
    ("common/non_ip/telegram", "REG"),
    ("common/non_ip/stream", "REG"),
    ("AppleStore", "APPLE"),
    ("common/non_ip/apple_cn", "DIRECT"),
    ("common/non_ip/domestic", "DIRECT"),
    ("common/non_ip/direct", "DIRECT"),
    ("common/non_ip/global", "REG"),
    ("common/ip/ai", "AI"),
    ("common/ip/telegram", "REG"),
    ("common/ip/telegram_asn", "REG"),
    ("common/ip/stream", "REG"),
    ("common/ip/domestic", "DIRECT"),
    ("common/ip/china_ip", "DIRECT"),
)

PROFILE_TOKENS = {
    "surge/profiles/Universal.conf": tuple(
        f"/surge/rules/{name}.list," for name, _ in RULESETS
    ),
    "surge/profiles/iOS.conf": tuple(
        f"/surge/rules/{name}.list," for name, _ in RULESETS
    ),
    "shadowrocket/profiles/Universal.conf": tuple(
        f"/shadowrocket/rules/{name}.list," for name, _ in RULESETS
    ),
    "clash-verge/profiles/Universal.yaml": (
        "RULE-SET,BinanceDirect,DIRECT",
        "RULE-SET,Binance,Binance",
        "RULE-SET,BybitDirect,DIRECT",
        "RULE-SET,Bybit,Bybit",
        "RULE-SET,OKXDirect,DIRECT",
        "RULE-SET,OKX,OKX",
        "RULE-SET,CommonLanDomain,DIRECT",
        "RULE-SET,OpenAI,AI服务",
        "RULE-SET,CommonLanIP,DIRECT",
        "RULE-SET,APNs,APNs-Proxy",
        "RULE-SET,Claude,AI服务",
        "RULE-SET,AI,AI服务",
        "RULE-SET,CommonAI,AI服务",
        "RULE-SET,CommonAppleIntelligence,AI服务",
        "RULE-SET,CommonTelegram,日常代理",
        "RULE-SET,CommonStream,日常代理",
        "RULE-SET,AppleStore,Apple商店",
        "RULE-SET,CommonAppleCN,DIRECT",
        "RULE-SET,CommonDomestic,DIRECT",
        "RULE-SET,CommonDirect,DIRECT",
        "RULE-SET,CommonGlobal,日常代理",
        "RULE-SET,CommonAIIP,AI服务",
        "RULE-SET,CommonTelegramIP,日常代理",
        "RULE-SET,CommonTelegramASN,日常代理",
        "RULE-SET,CommonStreamIP,日常代理",
        "RULE-SET,CommonDomesticIP,DIRECT",
        "RULE-SET,CommonChinaIP,DIRECT",
    ),
    "clash-verge/profiles/Full.yaml": (
        "RULE-SET,BinanceDirect,DIRECT",
        "RULE-SET,Binance,Binance",
        "RULE-SET,BybitDirect,DIRECT",
        "RULE-SET,Bybit,Bybit",
        "RULE-SET,OKXDirect,DIRECT",
        "RULE-SET,OKX,OKX",
        "RULE-SET,CommonLanDomain,DIRECT",
        "RULE-SET,OpenAI,AI服务",
        "RULE-SET,CommonLanIP,DIRECT",
        "RULE-SET,APNs,APNs-Proxy",
        "RULE-SET,Claude,AI服务",
        "RULE-SET,AI,AI服务",
        "RULE-SET,CommonAI,AI服务",
        "RULE-SET,CommonAppleIntelligence,AI服务",
        "RULE-SET,CommonTelegram,日常代理",
        "RULE-SET,CommonStream,日常代理",
        "RULE-SET,AppleStore,Apple商店",
        "RULE-SET,CommonAppleCN,DIRECT",
        "RULE-SET,CommonDomestic,DIRECT",
        "RULE-SET,CommonDirect,DIRECT",
        "RULE-SET,CommonGlobal,日常代理",
        "RULE-SET,CommonAIIP,AI服务",
        "RULE-SET,CommonTelegramIP,日常代理",
        "RULE-SET,CommonTelegramASN,日常代理",
        "RULE-SET,CommonStreamIP,日常代理",
        "RULE-SET,CommonDomesticIP,DIRECT",
        "RULE-SET,CommonChinaIP,DIRECT",
    ),
}

MANUAL_ONLY_PROFILES = {
    "surge/profiles/Universal.conf",
    "shadowrocket/profiles/Universal.conf",
    "clash-verge/profiles/Universal.yaml",
}

SURGE_OPENAI_EXTENDED_RULE = (
    "RULE-SET,https://raw.githubusercontent.com/Graham-lo/surge/master/"
    "surge/rules/OpenAI.list,AI服务,no-resolve,extended-matching"
)


@dataclass(frozen=True)
class Rule:
    order: int
    source: str
    policy: str
    kind: str
    value: str
    raw: str


def load_rules() -> list[Rule]:
    result: list[Rule] = []
    for order, (name, policy) in enumerate(RULESETS):
        source = f"surge/rules/{name}.list"
        path = ROOT / source
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw or raw.startswith(("#", ";", "//")):
                continue
            parts = raw.split(",")
            if len(parts) < 2:
                continue
            result.append(Rule(order, source, policy, parts[0], parts[1], raw))
    return result


def ordered_pair(left: Rule, right: Rule) -> tuple[str, ...]:
    first, second = (left, right) if left.order <= right.order else (right, left)
    return (
        first.raw,
        first.policy,
        first.source,
        second.raw,
        second.policy,
        second.source,
    )


def overlap_summary(rules: list[Rule]) -> dict[str, object]:
    exact: set[tuple[str, ...]] = set()
    by_raw: dict[str, list[Rule]] = {}
    for rule in rules:
        by_raw.setdefault(rule.raw, []).append(rule)
    for same_rules in by_raw.values():
        for index, left in enumerate(same_rules):
            for right in same_rules[index + 1 :]:
                if left.policy != right.policy:
                    exact.add(ordered_pair(left, right))

    domains = [rule for rule in rules if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}]
    domain_overlaps: set[tuple[str, ...]] = set()
    for index, left in enumerate(domains):
        left_value = left.value.lower().lstrip(".")
        for right in domains[index + 1 :]:
            if left.policy == right.policy:
                continue
            right_value = right.value.lower().lstrip(".")
            if left.kind == right.kind == "DOMAIN":
                overlaps = left_value == right_value
            elif left.kind == "DOMAIN":
                overlaps = left_value == right_value or left_value.endswith(f".{right_value}")
            elif right.kind == "DOMAIN":
                overlaps = right_value == left_value or right_value.endswith(f".{left_value}")
            else:
                overlaps = (
                    left_value == right_value
                    or left_value.endswith(f".{right_value}")
                    or right_value.endswith(f".{left_value}")
                )
            if overlaps:
                domain_overlaps.add(ordered_pair(left, right))

    networks: list[tuple[Rule, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for rule in rules:
        if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
            networks.append((rule, ipaddress.ip_network(rule.value, strict=False)))
    ip_overlaps: set[tuple[str, ...]] = set()
    for index, (left, left_network) in enumerate(networks):
        for right, right_network in networks[index + 1 :]:
            if left.policy == right.policy or left_network.version != right_network.version:
                continue
            if left_network.overlaps(right_network):
                ip_overlaps.add(ordered_pair(left, right))

    result: dict[str, object] = {"schema": 1}
    for name, values in (
        ("exact_cross_policy", exact),
        ("domain_cross_policy", domain_overlaps),
        ("ip_cross_policy", ip_overlaps),
    ):
        encoded = json.dumps(sorted(values), ensure_ascii=False, separators=(",", ":"))
        result[name] = {
            "count": len(values),
            "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        }
    return result


def surge_group_types(text: str) -> list[str]:
    """Return every active group type from a Surge-style [Proxy Group] section."""
    in_groups = False
    result: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_groups = line == "[Proxy Group]"
            continue
        if not in_groups or not line or line.startswith(("#", ";", "//")):
            continue
        if "=" in line:
            right = line.split("=", 1)[1]
            result.append(right.split(",", 1)[0].strip().lower())
    return result


def mihomo_group_types(text: str) -> list[str]:
    """Return every group type from the top-level Mihomo proxy-groups list."""
    in_groups = False
    result: list[str] = []
    for raw_line in text.splitlines():
        if raw_line == "proxy-groups:":
            in_groups = True
            continue
        if in_groups and raw_line and not raw_line[0].isspace():
            break
        if not in_groups:
            continue
        match = re.match(r"^\s+type:\s*([^\s#]+)", raw_line)
        if match:
            result.append(match.group(1).lower())
    return result


def check_profiles() -> list[str]:
    errors: list[str] = []
    for relative, tokens in PROFILE_TOKENS.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        positions = [text.find(token) for token in tokens]
        missing = [token for token, position in zip(tokens, positions) if position < 0]
        if missing:
            errors.append(f"{relative}: missing {len(missing)} ordered ruleset reference(s)")
        elif positions != sorted(positions):
            errors.append(f"{relative}: ruleset precedence differs from the audited order")
        if relative.startswith("surge/profiles/") and SURGE_OPENAI_EXTENDED_RULE not in text:
            errors.append(
                f"{relative}: OpenAI ruleset must enable no-resolve and extended-matching"
            )
        if relative in MANUAL_ONLY_PROFILES:
            group_types = (
                mihomo_group_types(text)
                if relative.endswith((".yaml", ".yml"))
                else surge_group_types(text)
            )
            invalid_types = sorted(set(group_types) - {"select"})
            if not group_types:
                errors.append(f"{relative}: no proxy groups found")
            elif invalid_types:
                errors.append(
                    f"{relative}: manual profile has non-select group types "
                    f"{', '.join(invalid_types)}"
                )
        if "ruleset.skk.moe" in text:
            errors.append(f"{relative}: public profile still depends on an external ruleset host")

    ios_text = (ROOT / "surge/profiles/iOS.conf").read_text(encoding="utf-8")
    for token in (
        "wifi-assist = true",
        "auto-suspend = false",
        "include-all-networks = true",
        "include-apns = true",
        "allow-wifi-access = false",
        "allow-hotspot-access = false",
        "udp-policy-not-supported-behaviour = REJECT",
        "日常代理 = smart,",
        "FAIL-CLOSED:1000",
        'AI服务 = select, AI自动容灾, include-all-proxies=true, policy-regex-filter="(?i)\\[AI\\]"',
        'Git服务 = select, Git自动容灾, DIRECT, include-all-proxies=true, policy-regex-filter="(?i)\\[GIT\\]"',
        "RULE-SET,https://raw.githubusercontent.com/Graham-lo/surge/master/surge/rules/APNs.list,APNs-Proxy,no-resolve,extended-matching",
    ):
        if token not in ios_text:
            errors.append(f"surge/profiles/iOS.conf: missing required iOS token {token!r}")
    ios_apple_group = next(
        (line for line in ios_text.splitlines() if line.startswith("Apple商店 = ")), ""
    )
    if "日常代理" in ios_apple_group:
        errors.append("surge/profiles/iOS.conf: Apple Store must not use the Smart group")

    full_text = (ROOT / "clash-verge/profiles/Full.yaml").read_text(encoding="utf-8")
    for token in (
        "allow-lan: false",
        "empty-fallback: REJECT",
        "type: url-test",
        "name: Git服务",
        "MATCH,日常代理",
    ):
        if token not in full_text:
            errors.append(f"clash-verge/profiles/Full.yaml: missing required token {token!r}")
    if "    - '*'" in full_text:
        errors.append("clash-verge/profiles/Full.yaml: fake-IP must not be disabled globally")
    apple_block = full_text.split("  - name: Apple商店", 1)[-1].split("  - name:", 1)[0]
    if "日常代理" in apple_block:
        errors.append("clash-verge/profiles/Full.yaml: Apple Store must not use the daily group")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="write a new overlap fingerprint after manually reviewing precedence",
    )
    args = parser.parse_args()
    summary = overlap_summary(load_rules())
    errors = check_profiles()

    if args.update_baseline:
        BASELINE.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print("Updated conflict-baseline.json; review it before committing.")
    elif not BASELINE.is_file():
        errors.append("conflict-baseline.json is missing")
    else:
        expected = json.loads(BASELINE.read_text(encoding="utf-8"))
        if summary != expected:
            errors.append(
                "cross-policy overlap fingerprint changed; review rules and run "
                "tools/check_rule_conflicts.py --update-baseline only if intentional"
            )

    if errors:
        for error in errors:
            print(f"Conflict audit failed: {error}", file=sys.stderr)
        return 1
    counts = ", ".join(
        f"{name}={details['count']}" for name, details in summary.items() if name != "schema"
    )
    print(f"Conflict audit passed ({counts}); first-match order is locked in all profiles.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
