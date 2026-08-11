# Shadowrocket

Import `profiles/Universal.conf` as the routing configuration, then import
private proxy subscriptions separately in Shadowrocket. The template contains
no subscription URL or node credential.

Use the same policy-name tags as the Surge template: `[AI]`, `[REG]`, `[BIN]`,
`[BYB]`, `[OKX]`, and `[TV]`. Prefix names with `[001]`, `[002]`, and so on to
keep score order obvious in the manual picker. All outbound groups are manual
`select` groups; this public profile does not switch exits automatically.

Files in `shadowrocket/rules` are generated from `surge/rules`. Do not edit the
generated copies directly. The common rules are full repository files and do
not redirect to an external rules project.
