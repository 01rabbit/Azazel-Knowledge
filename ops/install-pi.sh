#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ROOT_DIR=""
SECRETS_DEVICE=""
DATA_DEVICE=""
SKIP_ENCRYPTION=0
DATA_PARTITION_UNENCRYPTED=0
ACCEPT_SEIZURE_RECREATABLE_DATA=0
ACCEPT_CAPTURE_CONFIDENTIALITY_LOSS=0
SKIP_THERMAL=0
CHECK_ONLY=0
AUTO_YES=0

usage() {
  cat <<'EOF'
Usage:
  ops/install-pi.sh --root DIR [options]

Options:
  --root DIR
      Node working root (for example /srv/azazel-cti). Required.
  --secrets-device DEV
      Destructively format the secrets partition as LUKS2/Adiantum.
  --data-device DEV
      Destructively format the data partition as LUKS2/Adiantum.
  --skip-encryption
      Skip encryption and assume --root is already mounted.
  --data-partition-unencrypted --accept-seizure-recreatable-data
      Leave the data partition unencrypted only.
  --accept-capture-confidentiality-loss
      Accept unattended-boot keyfile auto-unlock risk and record the sign-off reminder.
  --skip-thermal
      Skip vcgencmd throttling checks.
  --check, --dry-run
      Run preflight only. No destructive action is performed.
  --yes
      Auto-approve destructive luksFormat/mkfs actions.
  -h, --help
      Show this help.
EOF
}

log() {
  printf '[%s] %s\n' "$1" "$2"
}

info() {
  log INFO "$1"
}

warn() {
  log WARN "$1" >&2
}

fail() {
  log ERROR "$1" >&2
  exit 1
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    return 1
  fi
}

require_cmd() {
  local cmd="$1"
  need_cmd "$cmd" || fail "required command not found: ${cmd}"
}

run_cmd() {
  info "$*"
  "$@"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --root)
        (($# >= 2)) || fail "--root requires a value"
        ROOT_DIR="$2"
        shift 2
        ;;
      --secrets-device)
        (($# >= 2)) || fail "--secrets-device requires a value"
        SECRETS_DEVICE="$2"
        shift 2
        ;;
      --data-device)
        (($# >= 2)) || fail "--data-device requires a value"
        DATA_DEVICE="$2"
        shift 2
        ;;
      --skip-encryption)
        SKIP_ENCRYPTION=1
        shift
        ;;
      --data-partition-unencrypted)
        DATA_PARTITION_UNENCRYPTED=1
        shift
        ;;
      --accept-seizure-recreatable-data)
        ACCEPT_SEIZURE_RECREATABLE_DATA=1
        shift
        ;;
      --accept-capture-confidentiality-loss)
        ACCEPT_CAPTURE_CONFIDENTIALITY_LOSS=1
        shift
        ;;
      --skip-thermal)
        SKIP_THERMAL=1
        shift
        ;;
      --check|--dry-run)
        CHECK_ONLY=1
        shift
        ;;
      --yes)
        AUTO_YES=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done
}

validate_args() {
  [[ -n "${ROOT_DIR}" ]] || fail "--root is required"

  if [[ "${SKIP_ENCRYPTION}" -eq 1 ]] && [[ -n "${SECRETS_DEVICE}${DATA_DEVICE}" ]]; then
    fail "--skip-encryption cannot be combined with device formatting options"
  fi

  if [[ "${DATA_PARTITION_UNENCRYPTED}" -eq 1 ]] && [[ "${ACCEPT_SEIZURE_RECREATABLE_DATA}" -ne 1 ]]; then
    fail "--data-partition-unencrypted requires --accept-seizure-recreatable-data"
  fi

  if [[ "${ACCEPT_SEIZURE_RECREATABLE_DATA}" -eq 1 ]] && [[ "${DATA_PARTITION_UNENCRYPTED}" -ne 1 ]]; then
    fail "--accept-seizure-recreatable-data requires --data-partition-unencrypted"
  fi

  if [[ "${DATA_PARTITION_UNENCRYPTED}" -eq 1 ]] && [[ -z "${DATA_DEVICE}" ]]; then
    fail "--data-partition-unencrypted requires --data-device"
  fi

  if [[ -n "${SECRETS_DEVICE}${DATA_DEVICE}" ]] && [[ "${AUTO_YES}" -ne 1 ]]; then
    fail "refusing destructive device formatting without --yes"
  fi
}

detect_repo_root() {
  if [[ -f "${ROOT_DIR}/azctl" && -f "${ROOT_DIR}/ops/docker-compose.yml" ]]; then
    printf '%s\n' "${ROOT_DIR}"
  else
    printf '%s\n' "${DEFAULT_REPO_ROOT}"
  fi
}

preflight() {
  local repo_root="$1"
  local status=0
  local uname_s uname_m

  info "preflight: validating host assumptions from ops/hardware-profile.md"
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"
  if [[ "${uname_s}" != "Linux" || "${uname_m}" != "aarch64" ]]; then
    warn "host is ${uname_s}/${uname_m}, expected Linux/aarch64 on Pi 4; allowing preflight for off-board development"
  else
    info "host platform: ${uname_s}/${uname_m}"
  fi

  if need_cmd docker; then
    info "docker: $(command -v docker)"
    if docker compose version >/dev/null 2>&1; then
      info "docker compose: available"
    else
      if [[ "${CHECK_ONLY}" -eq 1 ]]; then
        warn "docker compose not available; preflight warning only because --check was requested"
      else
        fail "docker compose not available"
      fi
    fi
  else
    if [[ "${CHECK_ONLY}" -eq 1 ]]; then
      warn "docker not available; preflight warning only because --check was requested"
    else
      fail "docker not available"
    fi
  fi

  if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    info "cgroup v2: present"
  else
    if [[ "${CHECK_ONLY}" -eq 1 ]]; then
      warn "cgroup v2 controller file missing; preflight warning only because --check was requested"
    else
      fail "cgroup v2 controller file missing: /sys/fs/cgroup/cgroup.controllers"
    fi
  fi

  if need_cmd findmnt; then
    info "root mount:"
    findmnt /
  else
    warn "findmnt not available; cannot display SSD boot evidence"
  fi

  if [[ "${SKIP_THERMAL}" -eq 1 ]]; then
    warn "thermal preflight skipped by --skip-thermal"
  elif need_cmd vcgencmd; then
    local throttled
    throttled="$(vcgencmd get_throttled 2>/dev/null || true)"
    info "vcgencmd get_throttled: ${throttled:-unavailable}"
    if [[ -n "${throttled}" && "${throttled}" != *"0x0"* ]]; then
      warn "thermal throttling history detected; hardware-profile latency claims are not trustworthy until cooling is fixed"
    fi
  else
    warn "vcgencmd not available; thermal throttling history not checked"
  fi

  if [[ ! -f "${repo_root}/azctl" ]]; then
    fail "azctl not found under ${repo_root}"
  fi
  if [[ ! -f "${repo_root}/ops/docker-compose.yml" ]]; then
    fail "docker-compose file not found under ${repo_root}/ops/docker-compose.yml"
  fi

  return "${status}"
}

run_azctl() {
  local repo_root="$1"
  shift

  if need_cmd python3; then
    (cd "${repo_root}" && python3 "${repo_root}/azctl" "$@")
    return
  fi
  if need_cmd python; then
    (cd "${repo_root}" && python "${repo_root}/azctl" "$@")
    return
  fi

  require_cmd docker
  info "host python not found; falling back to containerized azctl"
  docker run --rm \
    -v "${repo_root}:${repo_root}" \
    -w "${repo_root}" \
    azazel-cti:latest \
    python azctl "$@"
}

mount_if_needed() {
  local source="$1"
  local target="$2"
  mkdir -p "${target}"
  if mountpoint -q "${target}" 2>/dev/null; then
    info "mount already present: ${target}"
    return
  fi
  run_cmd mount "${source}" "${target}"
}

format_luks_partition() {
  local device="$1"
  local mapper_name="$2"
  local mount_dir="$3"

  require_cmd cryptsetup
  require_cmd mkfs.ext4
  require_cmd mount

  info "formatting ${device} as LUKS2/Adiantum per ops/hardware-profile.md §3"
  run_cmd cryptsetup luksFormat --type luks2 \
    --cipher xchacha12,aes-adiantum-plain64 \
    --key-size 256 \
    --pbkdf argon2id \
    "${device}"

  if [[ ! -e "/dev/mapper/${mapper_name}" ]]; then
    run_cmd cryptsetup open "${device}" "${mapper_name}"
  else
    info "mapper already open: /dev/mapper/${mapper_name}"
  fi

  run_cmd mkfs.ext4 "/dev/mapper/${mapper_name}"
  mount_if_needed "/dev/mapper/${mapper_name}" "${mount_dir}"
}

format_plain_partition() {
  local device="$1"
  local mount_dir="$2"

  require_cmd mkfs.ext4
  require_cmd mount

  warn "data partition left unencrypted by accepted-risk flag; record this in the site's threat-model sign-off"
  run_cmd mkfs.ext4 "${device}"
  mount_if_needed "${device}" "${mount_dir}"
}

setup_storage() {
  mkdir -p "${ROOT_DIR}"

  if [[ -n "${SECRETS_DEVICE}" ]]; then
    format_luks_partition "${SECRETS_DEVICE}" "azazel-secrets" "${ROOT_DIR}/secrets"
  fi

  if [[ -n "${DATA_DEVICE}" ]]; then
    if [[ "${DATA_PARTITION_UNENCRYPTED}" -eq 1 ]]; then
      format_plain_partition "${DATA_DEVICE}" "${ROOT_DIR}/data"
    else
      format_luks_partition "${DATA_DEVICE}" "azazel-data" "${ROOT_DIR}/data"
    fi
  fi

  mkdir -p "${ROOT_DIR}/var"
}

wait_for_health() {
  local repo_root="$1"
  local token="$2"
  local attempt=1
  local max_attempts=30
  local url="http://127.0.0.1:8443/v1/health"

  require_cmd curl

  while ((attempt <= max_attempts)); do
    if curl -fsS -H "Authorization: Bearer ${token}" "${url}" >/dev/null; then
      info "health check succeeded: HTTP 200 from ${url}"
      return 0
    fi
    info "health check pending (${attempt}/${max_attempts})"
    sleep 2
    attempt=$((attempt + 1))
  done

  fail "timed out waiting for ${url}"
}

main() {
  parse_args "$@"
  validate_args

  ROOT_DIR="$(cd "$(dirname "${ROOT_DIR}")" && pwd)/$(basename "${ROOT_DIR}")"
  local repo_root
  repo_root="$(detect_repo_root)"

  preflight "${repo_root}"

  if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    info "preflight completed; --check requested, exiting without side effects"
    return 0
  fi

  info "storage stage"
  if [[ "${SKIP_ENCRYPTION}" -eq 1 || ( -z "${SECRETS_DEVICE}" && -z "${DATA_DEVICE}" ) ]]; then
    warn "skipping encryption setup; assuming ${ROOT_DIR} is already mounted and threat-model sign-off records this choice"
    mkdir -p "${ROOT_DIR}" "${ROOT_DIR}/var"
  else
    setup_storage
  fi

  if [[ "${ACCEPT_CAPTURE_CONFIDENTIALITY_LOSS}" -eq 1 ]]; then
    warn "accepted-risk flag enabled: record unattended keyfile auto-unlock in the site's threat-model sign-off"
  fi

  info "provision stage"
  if [[ "${SKIP_THERMAL}" -eq 1 ]]; then
    run_azctl "${repo_root}" provision --root "${ROOT_DIR}"
  else
    run_azctl "${repo_root}" provision --root "${ROOT_DIR}" --check-thermal
  fi

  info "check-config stage"
  run_azctl "${repo_root}" check-config --config-dir "${repo_root}/config"

  info "startup stage"
  (
    cd "${repo_root}"
    docker compose -f ops/docker-compose.yml up -d --build
  )

  info "client bootstrap stage"
  local client_output token
  client_output="$(run_azctl "${repo_root}" client add --root "${ROOT_DIR}" --scopes read)"
  printf '%s\n' "${client_output}"
  token="$(printf '%s\n' "${client_output}" | sed -n 's/^token (shown once): //p' | tail -n 1)"
  [[ -n "${token}" ]] || fail "could not parse read-scope client token from azctl output"

  info "health wait stage"
  wait_for_health "${repo_root}" "${token}"

  cat <<EOF
[INFO] next steps
Import an offline intelligence bundle before trusting live context:
  $(basename "${repo_root}")/azctl bundle import --root ${ROOT_DIR} <bundle.tar.gz> --confirm
EOF
}

main "$@"
