# Surge

`surge/rules` is the repository's source of truth. The `common/` subtree holds
full static common rules in this repository; it is not a list of external
references. Edit these source files, then run `python3 tools/build_rules.py` to
refresh every client format.

`surge/profiles/Universal.conf` is the node-free manual template shared by Surge
Mac and Surge iOS. `surge/profiles/iOS.conf` is a standalone mobile template
with the complete exchange, AI, APNs, Apple Store, TradingView, Git and daily
routing topology. Both load only `Private-Proxies.dconf`; public rules stay
inline for compatibility with the current stable Surge parser. Add local rule
fragments at the top of `[Rule]` in a private profile copy. Copy the proxy
example, rename it, and keep it local. All private filenames are ignored by Git.

Policy tags control membership without exposing provider names:

- `[AI]`: clean residential policies for AI.
- `[REG]`: normal daily policies.
- `[MEDIA]`: selected high-throughput Telegram and streaming policies; IP purity is not a ranking input.
- `[BIN]`, `[BYB]`, `[OKX]`: exchange-specific candidates.
- `[TV]`, `[APNS]`, `[APPLE]`, `[GIT]`: service-specific candidates.
- `[PREFERRED]`: optional priority boost in the iOS Smart group.
- `[001]`, `[002]`, etc.: display/fallback order; lower numbers sort first.

The cross-platform Universal template uses manual `select` groups only. The iOS
template uses score-prefixed fallback groups, a quality-based Smart daily group,
and manual outer groups for sensitive services. Neither profile contains a
proxy server, subscription URL, credential, API key, local certificate, or MITM
password.

## Standalone iOS behavior

The iOS profile enables Wi-Fi Assist, Include All Networks and APNs takeover so
the APNs policy is actually evaluated. It disables Wi-Fi/Hotspot proxy sharing
and automatic suspension behind a Surge Mac gateway. If the phone is normally
used behind such a gateway, set `auto-suspend=true` locally to avoid double
processing. Include All Networks may interfere with AirDrop or USB Dashboard;
disable it together with `include-apns` if those integrations take priority.

The `[998][AI][REG][TV] FAIL-CLOSED` entry is an unreachable loopback sentinel,
not a remote node. Keep it active so an empty sensitive automatic group fails
instead of silently substituting DIRECT. The `[999][APNS] DIRECT` entry is a
built-in direct alias. Keep private candidates score-prefixed from `[001]`
upward so these sentinels remain last. Surge iOS uses the global
`proxy-test-url`; legacy group `url=` parameters are intentionally absent because
current Surge versions ignore them.

## Apple Store routing

`AppleStore.list` keeps App Store content, purchase, receipt and Apple Account
authentication on one manually selected egress. Its reference must stay after
the streaming rules, so Apple Music and TV exceptions win first, and before
`apple_cn`, domestic IP, SYSTEM and FINAL rules. The public group defaults to
DIRECT; private gateway profiles may add one fixed, audited backup node but
must not use a Smart group as the backup.

## Claude on an iOS gateway

Surge Mac cannot see the originating app process for traffic taken over from an
iPhone. Claude's shared Datadog, Sift, RevenueCat and Firebase endpoints must
therefore be paired with the phone's source address instead of being added as
unscoped domains to the public Claude ruleset. Copy the rules from
`Private-Rules.example.dconf` to the top of `[Rule]` in a private Universal
profile copy, reserve the phone's DHCP address, and replace the example address.
Keep these rules before the public Claude ruleset so telemetry and risk-control
traffic uses the same AI exit as the main Claude connection.

These gateway rules are not for `iOS.conf`. Put truly device-local overrides
directly at the top of its `[Rule]` section without a source-address wrapper.
