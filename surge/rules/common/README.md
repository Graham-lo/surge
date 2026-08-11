# Common rules

These are full, version-controlled Surge rule files. They are part of this
repository's editable source and are served directly from Graham-lo/surge;
clients do not follow or require another rules repository.

The initial snapshot and hashes are recorded in `common-rules.lock.json`.
Normal changes should be made directly in this directory. After editing, run:

```bash
python3 tools/build_rules.py
python3 tools/check_rule_conflicts.py
```

The generated Shadowrocket and Clash Verge versions are stored in their own
platform directories. Source attribution and license details are documented in
`THIRD_PARTY_NOTICES.md`.
