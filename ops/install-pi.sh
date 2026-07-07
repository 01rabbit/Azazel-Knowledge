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
INSTALL_SYSTEMD=0
SYSTEMD_UNIT_NAME="azazel-cti"
SYSTEMD_NO_START=0
EDGE_ADDR=""
MGMT_IP=""
BIND_PORT="8443"

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
  --install-systemd
      Render and install a systemd unit for docker compose boot persistence.
  --systemd-unit-name NAME
      Override the installed systemd unit name. Default: azazel-cti.
  --no-start
      Enable the systemd unit without starting it immediately.
  --edge-addr IP
      Edge or management-segment host IP to validate against MGMT_SEGMENT.
  --mgmt-ip IP
      Override the node management IP used for Edge connectivity checks.
  --bind-port PORT
      API bind port to verify. Default: 8443.
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
      --install-systemd)
        INSTALL_SYSTEMD=1
        shift
        ;;
      --systemd-unit-name)
        (($# >= 2)) || fail "--systemd-unit-name requires a value"
        SYSTEMD_UNIT_NAME="$2"
        shift 2
        ;;
      --no-start)
        SYSTEMD_NO_START=1
        shift
        ;;
      --edge-addr)
        (($# >= 2)) || fail "--edge-addr requires a value"
        EDGE_ADDR="$2"
        shift 2
        ;;
      --mgmt-ip)
        (($# >= 2)) || fail "--mgmt-ip requires a value"
        MGMT_IP="$2"
        shift 2
        ;;
      --bind-port)
        (($# >= 2)) || fail "--bind-port requires a value"
        BIND_PORT="$2"
        shift 2
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

  [[ "${SYSTEMD_UNIT_NAME}" =~ ^[A-Za-z0-9_.@-]+$ ]] || fail "--systemd-unit-name contains unsupported characters"
  [[ "${BIND_PORT}" =~ ^[0-9]+$ ]] || fail "--bind-port must be numeric"
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

  if [[ "${INSTALL_SYSTEMD}" -eq 1 ]]; then
    if [[ "${uname_s}" != "Linux" ]]; then
      info "systemd installation is only applicable on Linux; non-Linux host will preview or skip it"
    elif ! need_cmd systemctl; then
      if [[ "${CHECK_ONLY}" -eq 1 ]]; then
        warn "systemctl not available; --check will only render the unit preview"
      else
        fail "systemctl not available"
      fi
    else
      info "systemctl: $(command -v systemctl)"
    fi
  fi

  return "${status}"
}

normalize_systemd_unit_name() {
  if [[ "${SYSTEMD_UNIT_NAME}" == *.service ]]; then
    printf '%s\n' "${SYSTEMD_UNIT_NAME}"
  else
    printf '%s.service\n' "${SYSTEMD_UNIT_NAME}"
  fi
}

render_systemd_unit() {
  local repo_root="$1"
  local docker_bin="$2"
  local compose_file="${repo_root}/ops/docker-compose.yml"
  local template="${repo_root}/ops/azazel-cti.service"

  [[ -f "${template}" ]] || fail "systemd template not found under ${template}"

  sed \
    -e "s|__ROOT_DIR__|${ROOT_DIR}|g" \
    -e "s|__REPO_DIR__|${repo_root}|g" \
    -e "s|__DOCKER__|${docker_bin}|g" \
    -e "s|__COMPOSE_FILE__|${compose_file}|g" \
    "${template}"
}

preview_systemd_unit() {
  local repo_root="$1"
  local docker_bin="$2"
  local unit_name

  unit_name="$(normalize_systemd_unit_name)"
  info "systemd unit preview: /etc/systemd/system/${unit_name}"
  render_systemd_unit "${repo_root}" "${docker_bin}"
}

install_systemd_unit() {
  local repo_root="$1"
  local docker_bin="$2"
  local unit_name unit_path

  unit_name="$(normalize_systemd_unit_name)"
  unit_path="/etc/systemd/system/${unit_name}"

  info "systemd install stage"
  render_systemd_unit "${repo_root}" "${docker_bin}" >"${unit_path}"
  run_cmd systemctl daemon-reload
  if [[ "${SYSTEMD_NO_START}" -eq 1 ]]; then
    run_cmd systemctl enable "${unit_name}"
  else
    run_cmd systemctl enable --now "${unit_name}"
  fi
  run_cmd systemctl is-enabled "${unit_name}"
  run_cmd systemctl status --no-pager "${unit_name}"
}

detect_mgmt_ip() {
  if [[ -n "${MGMT_IP}" ]]; then
    printf '%s\n' "${MGMT_IP}"
    return
  fi

  if need_cmd ip; then
    local route_src
    route_src="$(
      ip -4 route get 1.1.1.1 2>/dev/null \
        | sed -n 's/.* src \([0-9.]\+\).*/\1/p' \
        | head -n 1
    )"
    if [[ -n "${route_src}" ]]; then
      printf '%s\n' "${route_src}"
      return
    fi
  fi

  if need_cmd hostname; then
    local hostname_ip
    hostname_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -n "${hostname_ip}" ]]; then
      printf '%s\n' "${hostname_ip}"
      return
    fi
  fi

  warn "could not auto-detect management IP; falling back to 127.0.0.1"
  printf '%s\n' "127.0.0.1"
}

extract_mgmt_segment() {
  local repo_root="$1"
  sed -n 's/^[[:space:]]*define MGMT_SEGMENT = \([^[:space:]#][^[:space:]#]*\).*/\1/p' "${repo_root}/ops/nftables.conf" | head -n 1
}

check_nftables_rule() {
  local port="$1"

  if ! need_cmd nft; then
    warn "nft command not available; nftables state not inspected"
    return 0
  fi

  local ruleset
  if ! ruleset="$(nft list ruleset 2>/dev/null)"; then
    warn "nftables ruleset unavailable; nftables may not be applied. Run: nft -f ops/nftables.conf"
    return 0
  fi

  if printf '%s\n' "${ruleset}" | grep -Eq "tcp dport ${port} accept"; then
    info "nftables runtime rule present for tcp dport ${port}"
  else
    warn "nftables runtime accept rule for tcp dport ${port} not found; run: nft -f ops/nftables.conf"
  fi
}

ip_in_cidr() {
  local ip="$1"
  local cidr="$2"

  python3 - "$ip" "$cidr" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1])
network = ipaddress.ip_network(sys.argv[2], strict=False)
raise SystemExit(0 if ip in network else 1)
PY
}

check_edge_addr_against_segment() {
  local edge_ip="$1"
  local mgmt_segment="$2"
  local allow_ping="$3"

  if [[ -z "${edge_ip}" || -z "${mgmt_segment}" ]]; then
    return 0
  fi

  if ip_in_cidr "${edge_ip}" "${mgmt_segment}"; then
    info "edge address ${edge_ip} is within MGMT_SEGMENT ${mgmt_segment}"
  else
    warn "edge address ${edge_ip} is outside MGMT_SEGMENT ${mgmt_segment}; nftables would drop it"
  fi

  if [[ "${allow_ping}" -ne 1 ]]; then
    return 0
  fi

  if need_cmd ping; then
    if ping -c1 -W1 "${edge_ip}" >/dev/null 2>&1; then
      info "edge L3 reachability probe succeeded: ping ${edge_ip}"
    else
      info "edge L3 reachability probe failed or filtered: ping ${edge_ip}"
    fi
  else
    info "ping not available; skipping optional L3 reachability probe for ${edge_ip}"
  fi
}

run_edge_check() {
  local repo_root="$1"
  local token="$2"
  local live_mode="$3"
  local mgmt_ip mgmt_segment url http_code

  info "edge connectivity stage"
  mgmt_ip="$(detect_mgmt_ip)"
  info "management IP for Edge connectivity: ${mgmt_ip}"

  mgmt_segment="$(extract_mgmt_segment "${repo_root}")"
  if [[ -n "${mgmt_segment}" ]]; then
    info "MGMT_SEGMENT from ops/nftables.conf: ${mgmt_segment}"
  else
    warn "could not extract MGMT_SEGMENT from ops/nftables.conf"
  fi

  if [[ -n "${EDGE_ADDR}" ]]; then
    check_edge_addr_against_segment "${EDGE_ADDR}" "${mgmt_segment}" "${live_mode}"
  fi

  url="http://${mgmt_ip}:${BIND_PORT}/v1/health"
  if [[ "${live_mode}" -eq 1 ]]; then
    check_nftables_rule "${BIND_PORT}"
    require_cmd curl
    http_code="$(
      curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer ${token}" \
        "${url}"
    )"
    if [[ "${http_code}" != "200" ]]; then
      fail "off-loopback health check failed for ${url} (HTTP ${http_code}); check bind address, nftables, and management segment routing"
    fi
    info "off-loopback health check succeeded: HTTP 200 from ${url}"
  else
    info "check-only mode: skipping live curl against ${url}"
  fi

  info "Edge should use: http://${mgmt_ip}:${BIND_PORT} (bearer token required)"
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
  local docker_bin=""

  preflight "${repo_root}"

  if need_cmd docker; then
    docker_bin="$(command -v docker)"
  fi

  if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    if [[ "${INSTALL_SYSTEMD}" -eq 1 ]]; then
      if [[ "$(uname -s)" != "Linux" ]]; then
        info "systemd install would be skipped on non-Linux host; rendering preview only during --check"
      elif ! need_cmd systemctl; then
        warn "systemctl not available; cannot install systemd unit on this host"
      fi
      preview_systemd_unit "${repo_root}" "${docker_bin:-docker}"
    fi

    if [[ -n "${EDGE_ADDR}${MGMT_IP}" || "${BIND_PORT}" != "8443" ]]; then
      run_edge_check "${repo_root}" "" 0
    fi

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

  run_edge_check "${repo_root}" "${token}" 1

  if [[ "${INSTALL_SYSTEMD}" -eq 1 ]]; then
    if [[ "$(uname -s)" != "Linux" ]]; then
      info "systemd install skipped on non-Linux host"
    else
      need_cmd systemctl || fail "systemctl not available"
      install_systemd_unit "${repo_root}" "${docker_bin}"
    fi
  else
    info "boot persistence not installed; rerun with --install-systemd to enable startup on reboot"
  fi

  cat <<EOF
[INFO] next steps
Import an offline intelligence bundle before trusting live context:
  $(basename "${repo_root}")/azctl bundle import --root ${ROOT_DIR} <bundle.tar.gz> --confirm
EOF
}

main "$@"
