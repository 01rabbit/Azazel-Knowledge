from __future__ import annotations

from pathlib import Path

from azazel_cti.normalize.exclusions import Decision, ExclusionPolicy


def test_is_bogon_rfc1918():
    assert ExclusionPolicy.is_bogon("10.1.2.3")
    assert ExclusionPolicy.is_bogon("172.16.0.5")
    assert ExclusionPolicy.is_bogon("192.168.1.1")


def test_is_bogon_loopback_and_link_local():
    assert ExclusionPolicy.is_bogon("127.0.0.1")
    assert ExclusionPolicy.is_bogon("169.254.1.1")
    assert ExclusionPolicy.is_bogon("::1")
    assert ExclusionPolicy.is_bogon("fe80::1")


def test_is_bogon_multicast_and_reserved():
    assert ExclusionPolicy.is_bogon("224.0.0.1")
    assert ExclusionPolicy.is_bogon("240.0.0.1")


def test_is_bogon_zero_net_and_docs():
    assert ExclusionPolicy.is_bogon("0.0.0.0")
    assert ExclusionPolicy.is_bogon("192.0.2.5")
    assert ExclusionPolicy.is_bogon("198.51.100.5")
    assert ExclusionPolicy.is_bogon("203.0.113.5")


def test_is_bogon_public_ip_false():
    assert not ExclusionPolicy.is_bogon("8.8.8.8")
    assert not ExclusionPolicy.is_bogon("93.184.216.34")


def test_is_bogon_invalid_ip_false():
    assert not ExclusionPolicy.is_bogon("not-an-ip")


def test_own_infra_match_by_network():
    policy = ExclusionPolicy(["203.0.113.0/24"], [])
    assert policy.is_own_infra("ip", "203.0.113.9")
    assert not policy.is_own_infra("ip", "203.0.114.9")


def test_critical_infra_flag_and_quarantine():
    policy = ExclusionPolicy([], [{"cidr": "93.184.216.0/24", "label": "scada"}])
    assert policy.is_critical_infra("ip", "93.184.216.10") is Decision.QUARANTINE_FLAG


def test_critical_infra_accept_when_not_matched():
    policy = ExclusionPolicy([], [{"cidr": "93.184.216.0/24", "label": "scada"}])
    assert policy.is_critical_infra("ip", "1.2.3.4") is Decision.ACCEPT


def test_bogon_takes_precedence_as_reject():
    policy = ExclusionPolicy([], [{"cidr": "10.0.0.0/8", "label": "internal-critical"}])
    assert policy.is_critical_infra("ip", "10.1.1.1") is Decision.REJECT


def test_own_infra_takes_precedence_over_critical_flag():
    policy = ExclusionPolicy(
        ["203.0.113.0/24"],
        [{"cidr": "203.0.113.0/24", "label": "dup"}],
    )
    assert policy.is_critical_infra("ip", "203.0.113.9") is Decision.REJECT


def test_from_yaml_file_loads_empty_lists(tmp_path: Path):
    yaml_text = "own_networks: []\ncritical_infrastructure: []\n"
    path = tmp_path / "own_infrastructure.yaml"
    path.write_text(yaml_text)
    policy = ExclusionPolicy.from_yaml_file(path)
    assert policy.is_critical_infra("ip", "8.8.8.8") is Decision.ACCEPT


def test_from_yaml_file_loads_populated_lists(tmp_path: Path):
    yaml_text = (
        "own_networks:\n"
        "  - 203.0.113.0/24\n"
        "critical_infrastructure:\n"
        "  - cidr: 93.184.216.0/24\n"
        "    label: scada\n"
    )
    path = tmp_path / "own_infrastructure.yaml"
    path.write_text(yaml_text)
    policy = ExclusionPolicy.from_yaml_file(path)
    assert policy.is_own_infra("ip", "203.0.113.5")
    assert policy.is_critical_infra("ip", "93.184.216.5") is Decision.QUARANTINE_FLAG


def test_repo_config_file_loads():
    repo_root = Path(__file__).resolve().parent.parent.parent
    config_path = repo_root / "config" / "own_infrastructure.yaml"
    policy = ExclusionPolicy.from_yaml_file(config_path)
    assert policy.is_critical_infra("ip", "8.8.8.8") is Decision.ACCEPT
