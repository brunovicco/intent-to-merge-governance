#!/usr/bin/env bash
# No publication or signing. Retain failed scanner reports and fail closed.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-results/public-security}"
case "$OUT" in results/*) ;; *) echo 'Output must be under results/' >&2; exit 2;; esac
mkdir -p "$(dirname "$OUT")"
mkdir "$OUT"
python3 scripts/release_inventory.py verify --require-lock > "$OUT/inventory.json"
uv lock --check
uv export --locked --extra telemetry --no-dev --format cyclonedx1.5 --output-file "$OUT/runtime.cdx.json"
uv export --locked --extra telemetry --no-dev --no-emit-project --output-file "$OUT/requirements.txt"
rc=0
python3 scripts/secret_preflight.py > "$OUT/secret-preflight.json" || rc=1
uvx --from pip-audit==2.9.0 pip-audit --require-hashes --disable-pip -r "$OUT/requirements.txt" -f json -o "$OUT/pip-audit.json" || rc=1
bandit_rc=0
uvx --python 3.11 --from bandit==1.8.6 bandit -r src scripts -f json -o "$OUT/bandit.json" || bandit_rc=$?
if [ "$bandit_rc" -le 1 ]; then
  python3 scripts/review_bandit.py --report "$OUT/bandit.json" > "$OUT/bandit-review.json" || rc=1
else
  rc=1
fi
# A full history/entropy scanner is a separate explicit prerequisite.
if command -v gitleaks >/dev/null 2>&1; then
  SCAN_ROOT=$(mktemp -d)
  trap 'rm -rf -- "$SCAN_ROOT"' EXIT
  python3 - "$SCAN_ROOT" <<'PYSCAN'
import shutil, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from release_inventory import ROOT, files, INVENTORY
snapshot = Path(sys.argv[1])
for rel in [*files(ROOT), INVENTORY]:
    dest = snapshot / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / rel, dest)
PYSCAN
  leaks_rc=0
  gitleaks dir "$SCAN_ROOT" --redact --no-banner --exit-code 23 --report-format json --report-path "$OUT/gitleaks.json" || leaks_rc=$?
  if [ "$leaks_rc" -eq 23 ]; then
    python3 scripts/review_gitleaks.py --root "$SCAN_ROOT" --report "$OUT/gitleaks.json" > "$OUT/gitleaks-review.json" || rc=1
  elif [ "$leaks_rc" -ne 0 ]; then
    rc=1
  fi
else
  echo 'gitleaks not available; full scanner pending' >&2
  rc=1
fi
printf '{"status":"%s","publication_ready":false,"merge_authority":false}\n' "$(if [ "$rc" -eq 0 ]; then echo SCANS_COMPLETED_REVIEW_REQUIRED; else echo REVIEW_OR_ERROR; fi)" > "$OUT/status.json"
cat "$OUT/status.json"
exit "$rc"
