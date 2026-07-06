# Hardware profile: Raspberry Pi 4 (design S7/S9/S11)

Reference board for Phase 1: Raspberry Pi 4 Model B, 8 GB RAM, SSD boot
(no SD card in the write path), Cortex-A72 (no AES instruction
extensions -- this is why Adiantum, not AES-XTS, is mandatory below).
This document is operational notes only; nothing here is executed by
`azctl` or the worker.

## 1. SSD boot

Boot from USB3-attached SSD, not the SD card:

```
raspi-config  # Advanced Options -> Boot Order -> USB Boot
```

Confirm the root filesystem is the SSD (`findmnt /`) before proceeding
to partitioning. The SD card, if left inserted, should carry nothing
except the bootloader/firmware partition.

## 2. Partitions

Two partitions carry the node's state, both LUKS2/Adiantum (design F-18):

- **secrets partition** -- `secrets/` (node signing key, `trust/anchors.toml`,
  `trust/state.toml`, `local.db`'s `api_client` tokens are hashed, but the
  audit chain and `local.db` file itself live here too).
- **data partition** -- `data/db/gen-*/intel.db`, `var/ingest/*` spools.

## 3. LUKS2 with Adiantum

Cortex-A72 has no AES hardware acceleration, and every query and ingest
line takes a write on the LUKS-resident chain/DB files, so software
AES-XTS is explicitly excluded (design F-18). Use Adiantum instead:

```sh
# Secrets partition
cryptsetup luksFormat --type luks2 \
  --cipher xchacha12,aes-adiantum-plain64 \
  --key-size 256 \
  --pbkdf argon2id \
  /dev/sdX1

# Data partition
cryptsetup luksFormat --type luks2 \
  --cipher xchacha12,aes-adiantum-plain64 \
  --key-size 256 \
  --pbkdf argon2id \
  /dev/sdX2

cryptsetup open /dev/sdX1 azazel-secrets
cryptsetup open /dev/sdX2 azazel-data
mkfs.ext4 /dev/mapper/azazel-secrets
mkfs.ext4 /dev/mapper/azazel-data
```

Benchmark the board before committing to a passphrase-only unlock flow
-- Adiantum throughput varies noticeably across Pi 4 revisions:

```sh
cryptsetup benchmark --cipher xchacha12,aes-adiantum-plain64
```

Record the result here per deployed unit:

| Unit | `cryptsetup benchmark` xchacha12/adiantum (MiB/s) | Notes |
|---|---|---|
| _(fill in per board)_ | | |

## 4. Accepted-risk flags (design F-18, S7)

Both are opt-in, narrow, and logged; neither is a default:

- `--data-partition-unencrypted --accept-seizure-recreatable-data` --
  skips LUKS on the **data partition only** (never the secrets
  partition or `local.db`). Legitimate only because the intel tier is
  fully re-importable from a bundle; the local/research tier is never
  eligible for this flag under any circumstance.
- `--accept-capture-confidentiality-loss` -- enables keyfile
  auto-unlock at boot (no passphrase prompt) instead of an operator
  typing the LUKS passphrase over console/SSH at every power cycle.
  Trades confidentiality-under-capture for unattended-boot convenience;
  record explicitly in the site's threat-model sign-off if used.

`azctl provision` does not set either flag implicitly; an operator must
pass them, and they are audit-logged when they are.

## 5. cgroup memory caps and CPU reservation

Docker Compose (`ops/docker-compose.yml`) already sets `mem_limit:
1280m` (api) and `mem_limit: 640m` (worker), which map to the
container's memory cgroup (`memory.max` under cgroup v2). Confirm the
host is on cgroup v2 (`cat /sys/fs/cgroup/cgroup.controllers`) --
Raspberry Pi OS Bookworm defaults to v2; Bullseye needs
`cgroup_enable=memory cgroup_memory=1` added to `/boot/cmdline.txt`.

One core is reserved for the worker (`cpuset: "3"` in
docker-compose.yml, design S2/S9's writer-starvation gate) so a live
bundle build or feed pull never contends with the api's query-serving
cores. Adjust the index to the board's actual core count if it is ever
not a 4-core Pi 4.

## 6. Thermal check

The Pi 4 throttles at 80 C and hard-caps the clock at 85 C; a throttled
core invalidates every latency budget in design S9. `azctl provision
--check-thermal` reads `/sys/class/thermal/thermal_zone0/temp` (milli-C)
and prints the current reading, or "skipped" if no thermal zone is
present (e.g. running the dev checks off-board). For a sustained
production check, run alongside a load test:

```sh
vcgencmd get_throttled   # non-zero = throttling has occurred since boot
```

A non-zero `get_throttled` result after a capacity run means the S9
latency numbers from that run are not trustworthy -- fix cooling (heat
sink + fan, case airflow) before trusting a benchmark, not after.

## 7. Boot order recap

1. SSD boot confirmed (`findmnt /`).
2. Both partitions LUKS2/Adiantum-open (or accepted-risk flags recorded).
3. `docker compose -f ops/docker-compose.yml up -d`.
4. `azctl provision --root <mounted data root> --check-thermal` (first
   boot only) -- see [docs/operations.md](../docs/operations.md) for the
   full quickstart from here.
