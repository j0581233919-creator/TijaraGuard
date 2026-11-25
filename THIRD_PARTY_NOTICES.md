# Third-Party Notices and Upstream Attribution

TijaraGuard is licensed under the [MIT License](LICENSE). It integrates and distributes MIT-licensed source snapshots of three upstream components so that TijaraGuard runs cleanly out-of-the-box from a fresh checkout without requiring sibling directories on disk.

All upstream licenses and notices are preserved verbatim inside `tijaraguard/_vendor/<component>/`.

---

## 1. BayanGate (`bayan-gate`)

- **Upstream Repository:** https://github.com/j0581233919-creator/bayan-gate
- **Pinned Commit:** `1d6b83a46cb75484a434efe17be2e7d97885050c`
- **Version:** `1.0.1`
- **License:** MIT (`Copyright (c) 2026 BayanGate Contributors`)
- **Vendored Location:** `tijaraguard/_vendor/bayan_gate/`

## 2. CatalogCopilot (`catalog-copilot`)

- **Upstream Repository:** https://github.com/j0581233919-creator/catalog-copilot
- **Pinned Commit:** `12522d3b17767ae9a4766499b6495fd4231ebcfc`
- **Version:** `1.0.1`
- **License:** MIT (`Copyright (c) 2026 CatalogCopilot Contributors`)
- **Vendored Location:** `tijaraguard/_vendor/catalog_copilot/`

## 3. Message Shield (`message-shield`)

- **Upstream Repository:** https://github.com/j0581233919-creator/message-shield
- **Pinned Commit:** `4ccbc2641c18b47a9feadbe41010a06fb2791275`
- **Version:** `0.1.0`
- **License:** MIT (`Copyright (c) 2026 Message Shield contributors`)
- **Vendored Location:** `tijaraguard/_vendor/message_shield/`

---

## Python & SQLite Runtime Notice

TijaraGuard uses only the Python standard library and SQLite (`dependencies = []` in `pyproject.toml`). Users supply their own Python interpreter and SQLite runtime under their respective licenses:

- Python Software Foundation License: https://docs.python.org/3/license.html
- SQLite Public-Domain Dedication: https://sqlite.org/copyright.html
