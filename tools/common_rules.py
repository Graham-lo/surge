"""Definitions for common rules stored as editable Surge source files."""

from __future__ import annotations


UPSTREAM_REPOSITORY = "https://github.com/SukkaLab/ruleset.skk.moe"
UPSTREAM_API = "https://api.github.com/repos/SukkaLab/ruleset.skk.moe"
UPSTREAM_RAW = "https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe"

# These files are copied into this repository. Clients never fetch them from
# UPSTREAM_REPOSITORY; the upstream location is retained only for provenance
# and optional manual refreshes.
COMMON_RULE_PATHS = (
    "non_ip/lan",
    "ip/lan",
    "non_ip/ai",
    "non_ip/apple_intelligence",
    "non_ip/telegram",
    "non_ip/stream",
    "non_ip/apple_cn",
    "non_ip/domestic",
    "non_ip/direct",
    "non_ip/global",
    "ip/ai",
    "ip/telegram",
    "ip/telegram_asn",
    "ip/stream",
    "ip/domestic",
    "ip/china_ip",
)


def upstream_path(name: str) -> str:
    category, filename = name.split("/", 1)
    return f"List/{category}/{filename}.conf"


def license_for(name: str) -> str:
    return "CC-BY-SA-2.0" if name == "ip/china_ip" else "AGPL-3.0-only"
