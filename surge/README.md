# Surge

`surge/rules` is the repository's source of truth. The `common/` subtree holds
full static common rules in this repository; it is not a list of external
references. Edit these source files, then run `python3 tools/build_rules.py` to
refresh every client format.

`surge/profiles/Universal.conf` is a node-free template shared by Surge Mac and
Surge iOS. It intentionally loads a local detached profile named
`Private-Proxies.dconf` and `Private-Rules.dconf`; copy the corresponding
example files, rename them, and add private policies and client-scoped rules
locally. The private filenames are ignored by Git.

Policy tags control membership without exposing provider names:

- `[AI]`: clean residential policies for AI.
- `[REG]`: normal daily policies.
- `[BIN]`, `[BYB]`, `[OKX]`: exchange-specific candidates.
- `[TV]`: TradingView candidates.
- `[001]`, `[002]`, etc.: score order; lower numbers have higher priority.

The public template uses manual `select` groups only because it targets normal
phone and computer clients. It contains no automatic fallback, proxy server,
subscription URL, credential, API key, local certificate, or MITM password.

## Claude on an iOS gateway

Surge Mac cannot see the originating app process for traffic taken over from an
iPhone. Claude's shared Datadog, Sift, RevenueCat and Firebase endpoints must
therefore be paired with the phone's source address instead of being added as
unscoped domains to the public Claude ruleset. Copy
`Private-Rules.example.dconf` to `Private-Rules.dconf`, reserve the phone's DHCP
address, and replace the example address. Keep these rules before the public
Claude ruleset so telemetry and risk-control traffic uses the same AI exit as
the main Claude connection.
