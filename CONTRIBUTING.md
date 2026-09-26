# Contributing

Submit only public Web3 smart-contract security material.

## Required
- public source URL
- explicit severity evidence
- project / protocol name when known
- concise technical summary
- provenance note
- disclosure or publication context

## Do not submit
- secrets or private keys
- confidential audits or private bounty reports
- embargoed vulnerabilities
- live-target exploit instructions

Unknown fields should remain unknown rather than guessed.

Before opening a pull request, run:

python tools/validate_dataset.py
\n## New audit-layer checks\n\nBefore a pull request:\n\n```bash\npython tools/validate_dataset.py\npython tools/generate_audit_reports.py\npython tools/validate_audit_reports.py\n```\n\nThe generated audit layer must remain deterministic and must not rewrite legacy case files.\n