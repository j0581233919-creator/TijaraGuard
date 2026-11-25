# Reproducible Verification Commands

Run all commands from `/media/islam/shared pop/GitHub/tijaraguard-prototype`:

```bash
# 1. Run full deterministic unit, adversarial, concurrency, and crash-recovery tests
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v

# 2. Inspect read-only sibling dependency resolution
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard inspect-deps

# 3. Execute end-to-end synthetic Arabic business demo
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard demo --state-dir .state/verification-demo

# 4. Verify append-only audit hash chain on the demo ledger
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard verify-audit .state/verification-demo/ledger.sqlite3

# 5. Verify zero contamination in original read-only repositories
for repo in catalog-copilot bayan-gate message-shield quote-judge; do
  echo "=== $repo ==="
  git -C "/media/islam/shared pop/GitHub/$repo/repo" rev-parse HEAD
  git -C "/media/islam/shared pop/GitHub/$repo/repo" status --porcelain
done
```
