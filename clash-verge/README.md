# Clash Verge Rev / Mihomo

`profiles/Universal.yaml` is a node-free Mihomo configuration suitable for
Clash Verge Rev. Copy provider entries from `Proxy-Providers.example.yaml`
into a local copy and replace placeholders only on the device.

`profiles/Full.yaml` adds the complete exchange, AI, APNs, Apple Store,
TradingView, Git and daily routing topology. It is also node-free: provider
URLs stay in a private local copy. `allow-lan` is disabled, TUN is declared but
disabled for Clash Verge to control, and domain sniffing supplements fake-IP
matching without overriding the original destination.

Mihomo sorts included provider policies by name. Prefix or rename nodes with
`[001]`, `[002]`, and so on so the manual and fallback ordering follows the
maintained score. Put the score first, then add service tags (`[AI]`, `[REG]`,
`[BIN]`, `[BYB]`, `[OKX]`, `[TV]`, `[APNS]`, `[APPLE]`, `[GIT]`) through provider
overrides or subscription conversion.

Files in `clash-verge/rules` are generated `behavior: classical` providers from
the canonical Surge rules. Do not edit generated copies directly. All outbound
groups use manual `select`; no fallback or latency-triggered exit switching is
enabled in this public profile.

That last rule applies to `Universal.yaml`. `Full.yaml` uses lazy automatic
groups. AI, TradingView and daily groups fail closed with `REJECT` when no
matching provider policy exists; exchange and Git outer groups retain an
explicit DIRECT option, mirroring the maintained client behavior. Provider
health checks remain required because Mihomo group checks do not test policies
introduced from providers.
