# Graham Network Rules

This repository maintains node-free routing rules and generic configurations
for three clients. Proxy nodes, subscription URLs, credentials and local
certificates are intentionally excluded.

## Platforms

| Client | Rules | Generic profile |
| --- | --- | --- |
| Surge Mac / iOS | [`surge/rules`](surge/rules) | [`surge/profiles/Universal.conf`](surge/profiles/Universal.conf) |
| Shadowrocket | [`shadowrocket/rules`](shadowrocket/rules) | [`shadowrocket/profiles/Universal.conf`](shadowrocket/profiles/Universal.conf) |
| Clash Verge Rev / Mihomo | [`clash-verge/rules`](clash-verge/rules) | [`clash-verge/profiles/Universal.yaml`](clash-verge/profiles/Universal.yaml) |

The maintained service sets are AI, OpenAI, Claude, APNs, Binance, Bybit and
OKX. Sixteen common sets for LAN, AI, Apple Intelligence, Telegram, streaming,
domestic/global routing and IP routing are also stored in this repository as
editable static files. Clients do not fetch rules from another rules project.

Rules for Surge are canonical; the Shadowrocket and Clash Verge variants are
generated automatically. Public profiles use manual `select` groups only. The
automatic fallback groups used by the Mac mini gateway remain in its private
local profile and are intentionally not published here.

## Maintenance

```bash
python3 tools/build_rules.py
python3 tools/build_rules.py --check
python3 tools/check_rule_conflicts.py
python3 tools/check_secrets.py
```

`rules/` is a generated compatibility mirror for existing Surge URLs. New
profiles should use `surge/rules/`. `conflict-baseline.json` locks reviewed
cross-policy overlaps and first-match precedence. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the update workflow and validation
rules.

## Private configuration

Keep all private material outside this repository. The platform READMEs explain
how to attach local nodes or subscriptions. Use policy-name tags to keep the
same behavior across clients:

- `[AI]`: clean residential AI candidates.
- `[REG]`: normal daily candidates.
- `[BIN]`, `[BYB]`, `[OKX]`: exchange candidates.
- `[TV]`: TradingView candidates.
- `[001]`, `[002]`, etc.: score order, best first in the manual picker.

## Common rules and independence

The files below `surge/rules/common/` are repository-owned working copies. They
were initially imported from a reviewed snapshot, are committed in full, and
may be edited here even if the original project disappears. The source commit
and file hashes are recorded in `common-rules.lock.json`; licensing and
attribution are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Stable raw URLs

Example Surge URL:

```text
https://raw.githubusercontent.com/Graham-lo/surge/master/surge/rules/OpenAI.list
```

Example Shadowrocket URL:

```text
https://raw.githubusercontent.com/Graham-lo/surge/master/shadowrocket/rules/OpenAI.list
```

Example Clash Verge rule-provider URL:

```text
https://raw.githubusercontent.com/Graham-lo/surge/master/clash-verge/rules/OpenAI.yaml
```
