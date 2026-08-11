# Clash Verge Rev / Mihomo

`profiles/Universal.yaml` is a node-free Mihomo configuration suitable for
Clash Verge Rev. Copy provider entries from `Proxy-Providers.example.yaml`
into a local copy and replace placeholders only on the device.

Mihomo sorts included provider policies by name. Prefix or rename nodes with
`[001]`, `[002]`, and so on so the manual picker follows the maintained score.
Add service tags (`[AI]`, `[REG]`, `[BIN]`, `[BYB]`, `[OKX]`, `[TV]`) through
provider overrides or subscription conversion.

Files in `clash-verge/rules` are generated `behavior: classical` providers from
the canonical Surge rules. Do not edit generated copies directly. All outbound
groups use manual `select`; no fallback or latency-triggered exit switching is
enabled in this public profile.
