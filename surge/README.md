# Surge

`surge/rules` is the repository's source of truth. The `common/` subtree holds
full static common rules in this repository; it is not a list of external
references. Edit these source files, then run `python3 tools/build_rules.py` to
refresh every client format.

`surge/profiles/Universal.conf` is a node-free template shared by Surge Mac and
Surge iOS. It intentionally loads a local detached profile named
`Private-Proxies.dconf`; copy `Private-Proxies.example.dconf`, rename it, and
add private policies locally. The private filename is ignored by Git.

Policy tags control membership without exposing provider names:

- `[AI]`: clean residential policies for AI.
- `[REG]`: normal daily policies.
- `[BIN]`, `[BYB]`, `[OKX]`: exchange-specific candidates.
- `[TV]`: TradingView candidates.
- `[001]`, `[002]`, etc.: score order; lower numbers have higher priority.

The public template uses manual `select` groups only because it targets normal
phone and computer clients. It contains no automatic fallback, proxy server,
subscription URL, credential, API key, local certificate, or MITM password.
