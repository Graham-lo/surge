# Maintenance workflow

## Rule changes

1. Edit only files in `surge/rules/`.
2. Keep one policy-free rule per line. Comments may start with `#`, `;`, or `//`.
3. Run `python3 tools/build_rules.py`.
4. Run `python3 tools/check_rule_conflicts.py`. New cross-policy overlaps must
   be reviewed before updating the baseline with `--update-baseline`.
5. Run `python3 tools/build_rules.py --check` and `python3 tools/check_secrets.py`.
6. Review `rules-manifest.json` and the generated client files.

The build rejects duplicate rules, unsupported rule types, malformed domains,
invalid CIDRs, and unexpected policy fields. Shadowrocket generation omits
desktop-only rules containing `PROCESS-NAME`; the manifest keeps counts and a
SHA-256 digest of every canonical file.

## Common rule snapshots

Files in `surge/rules/common/` are static source files, not remote redirects.
Edit them directly for normal maintenance. If you intentionally want to replace
them with a newer snapshot of the original source, run:

```bash
python3 tools/import_common_rules.py --ref <reviewed-commit>
python3 tools/build_rules.py
python3 tools/check_rule_conflicts.py
```

The import command overwrites the common source files, so always use a specific
reviewed commit and inspect the diff. It is optional; client operation and local
maintenance never depend on the original repository.

## Adding another client

Add a renderer to `tools/build_rules.py`, give it a separate top-level client
directory, document the format, and include its output in `--check`. Never edit
generated client rules directly.

## Security

Do not commit:

- subscription URLs or URL-encoded subscriptions;
- proxy hostnames, ports, passwords, PSKs, UUIDs or authentication headers;
- private detached profiles;
- MITM certificates or passwords;
- API tokens or device credentials.

The secret scanner is a guardrail, not a substitute for reviewing the staged
diff before every push.
