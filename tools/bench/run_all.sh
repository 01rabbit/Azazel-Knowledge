#!/usr/bin/env bash
set -euo pipefail

# Run on the Pi 4 hardware profile documented in
# ../../ops/hardware-profile.md: SSD boot, LUKS2/Adiantum, cgroup limits,
# and reserved worker core are assumed when treating results as S9 gates.

ROOT="bench-results/scratch"
LABEL="run"
STAMP=""
CONFIG_DIR=""
REQUESTS="2000"
CONCURRENCY="8"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT="$2"
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --stamp)
      STAMP="$2"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    --requests)
      REQUESTS="$2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

run_thermal_check() {
  if command -v vcgencmd >/dev/null 2>&1; then
    local throttled
    throttled="$(vcgencmd get_throttled || true)"
    echo "thermal throttled state: ${throttled}"
    if [[ "${throttled}" != "throttled=0x0" ]]; then
      echo "WARNING: non-zero throttled state; benchmark results are not trustworthy for S9 gating" >&2
    fi
  else
    echo "thermal throttled state: vcgencmd unavailable"
  fi

  if [[ -r /sys/class/thermal/thermal_zone0/temp ]]; then
    echo "thermal temp mC: $(cat /sys/class/thermal/thermal_zone0/temp)"
  else
    echo "thermal temp mC: unavailable"
  fi
}

COMMON_ARGS=(--root "$ROOT" --label "$LABEL")
if [[ -n "$STAMP" ]]; then
  COMMON_ARGS+=(--stamp "$STAMP")
fi
if [[ -n "$CONFIG_DIR" ]]; then
  COMMON_ARGS+=(--config-dir "$CONFIG_DIR")
fi

run_thermal_check
python tools/bench/synth_dataset.py --root "$ROOT" --scale 1.0
python tools/bench/capacity_run.py "${COMMON_ARGS[@]}" --manifest bench-results/dataset-manifest.json --requests "$REQUESTS"
python tools/bench/availability_run.py "${COMMON_ARGS[@]}" --manifest bench-results/dataset-manifest.json --requests "$REQUESTS" --concurrency "$CONCURRENCY"
python tools/bench/cold_read.py "${COMMON_ARGS[@]}" --manifest bench-results/dataset-manifest.json
run_thermal_check

LABEL_ENV="$LABEL" python - <<'PY'
import json
import os
from pathlib import Path

label = os.environ["LABEL_ENV"]
paths = {
    "capacity": Path("bench-results") / f"capacity-{label}.json",
    "availability": Path("bench-results") / f"availability-{label}.json",
    "cold-read": Path("bench-results") / f"cold-read-{label}.json",
}
print("Gate summary:")
for name, path in paths.items():
    payload = json.loads(path.read_text(encoding="utf-8"))
    print(f"- {name}: pass={payload.get('pass')} authoritative={payload.get('authoritative')}")
    note = payload.get("note")
    if note:
        print(f"  {note}")
PY
