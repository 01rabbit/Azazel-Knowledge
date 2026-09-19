"""The deployment file must name things that actually exist, and probe them correctly.

`ops/docker-compose.yml` was once merged pointing at ``azazel_cti.api.app:app``
when no module-level ``app`` existed, so the API container could not start at
all (#10, reopened for that reason). Nothing in the suite noticed, because every
other test reaches the application through ``create_app()`` directly — the
wiring the deployment actually uses was the one path no test exercised. The
package has since been renamed, which is exactly the class of change that breaks
a string in a YAML file silently.

These tests read the deployment file and check that what it names resolves, that
its liveness probe accepts the status the application really returns, and that
the file keeps the two structural promises its own header makes: exactly two
containers, and one writer.

Deterministic (絶対制約3): the file is read from disk and parsed, and the probe
is executed against a stubbed opener. Nothing here reads a clock, a network, or
an environment variable that varies between runs.
"""

from __future__ import annotations

import importlib
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml
from _api_support import add_api_client, auth_header, make_client
from fastapi import FastAPI

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "ops" / "docker-compose.yml"

HEALTH_PATH = "/v1/health"

# design S11/S7 and the Phase-1 acceptance item: API + worker resident memory
# stays under 2 GB on the 8 GB Pi 4, leaving the rest for the OS and page cache.
MEMORY_CEILING_MIB = 2048

_SUFFIX_TO_MIB = {"m": 1, "g": 1024}


@pytest.fixture(scope="module")
def compose() -> dict:
    parsed = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict) and parsed.get("services"), (
        f"{COMPOSE} did not parse into a services mapping"
    )
    return parsed


def _mem_limit_mib(raw: str) -> int:
    value, suffix = raw[:-1], raw[-1].lower()
    assert suffix in _SUFFIX_TO_MIB, f"unhandled mem_limit unit in {raw!r}"
    return int(value) * _SUFFIX_TO_MIB[suffix]


def _data_mount(service: dict) -> str:
    mounts = [m for m in service["volumes"] if ":/app/data" in m]
    assert len(mounts) == 1, f"expected exactly one /app/data mount, got {mounts}"
    return mounts[0]


def _deployed_app(tmp_path, monkeypatch) -> FastAPI:
    """Import the ASGI target the way gunicorn would, outside the repo.

    Importing from a directory that is not the repo, with no AZAZEL_ROOT set,
    keeps a target that only resolves in the test environment from being
    mistaken for one that resolves in the container.
    """

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    monkeypatch.delenv("AZAZEL_CONFIG_DIR", raising=False)
    module = importlib.reload(
        sys.modules.get("azazel_knowledge.api.app")
        or importlib.import_module("azazel_knowledge.api.app")
    )
    return module.app


def _asgi_target(compose: dict) -> str:
    command = compose["services"]["api"]["command"]
    target = next(
        (arg for arg in command if ":" in arg and "/" not in arg and "." in arg), None
    )
    assert target, f"no module:attribute target found in the api command {command}"
    return target


def _probe_source(compose: dict) -> str:
    test_command = compose["services"]["api"]["healthcheck"]["test"]
    assert test_command[:3] == ["CMD", "python", "-c"], (
        f"unexpected healthcheck form {test_command[:3]}"
    )
    return test_command[3]


def test_the_api_service_names_an_asgi_app_that_exists(compose, tmp_path, monkeypatch):
    """The defect that reopened #10: a gunicorn target with no such attribute."""

    module_path, _, attribute = _asgi_target(compose).partition(":")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    monkeypatch.delenv("AZAZEL_CONFIG_DIR", raising=False)
    module = importlib.reload(
        sys.modules.get(module_path) or importlib.import_module(module_path)
    )
    app = getattr(module, attribute, None)
    assert isinstance(app, FastAPI), (
        f"{_asgi_target(compose)} is not an ASGI application — the api container "
        "cannot start"
    )


def test_the_deployed_app_serves_the_path_the_healthcheck_probes(
    compose, tmp_path, monkeypatch
):
    """A probe against a path that 404s marks a working container unhealthy."""

    assert HEALTH_PATH in _probe_source(compose), (
        f"the healthcheck no longer probes {HEALTH_PATH}"
    )
    served = _deployed_app(tmp_path, monkeypatch).openapi()["paths"]
    assert HEALTH_PATH in served, (
        f"{HEALTH_PATH} is not served; paths: {sorted(served)}"
    )


def test_the_health_route_requires_a_token(tmp_path):
    """Pin the contract the probe has to live with.

    `/v1/health` reports intel generation, cache state and audit-writer status.
    That is not for an unauthenticated caller on a published port, so it stays
    behind Scope.READ and the probe must cope with 401 rather than the route
    being opened up for the probe's convenience.
    """

    client, _settings, local_db_path, _ = make_client(tmp_path)
    assert client.get(HEALTH_PATH).status_code == 401
    token = add_api_client(local_db_path, "compose-probe", ["read"])
    assert client.get(HEALTH_PATH, headers=auth_header(token)).status_code == 200


@pytest.mark.parametrize(
    ("outcome", "expected_exit"),
    [
        ("200", 0),  # authenticated-equivalent success
        ("401", 0),  # unauthenticated but serving: live
        ("500", 1),  # serving an error: not live
        ("403", 1),  # a different refusal is not the one we accept
        ("refused", 1),  # nothing listening
    ],
)
def test_the_liveness_probe_accepts_exactly_the_live_outcomes(
    compose, outcome, expected_exit
):
    """Execute the probe the compose file really contains, not a paraphrase.

    Before this probe accepted 401, `docker compose up` marked a perfectly
    working container unhealthy forever, because the route it polls requires a
    token and `urlopen` raises on 401 (#10).
    """

    class _Response:
        def __init__(self, status: int) -> None:
            self.status = status

    def _opener(_url, timeout=None):
        if outcome == "refused":
            raise urllib.error.URLError("connection refused")
        code = int(outcome)
        if code >= 400:
            raise urllib.error.HTTPError(_url, code, "stub", {}, None)
        return _Response(code)

    # The probe does its own `import urllib.request`, so the stub is installed on
    # the module it will import. Nothing here opens a socket: a probe that
    # reached the network would make this test depend on what happens to be
    # listening (絶対制約3).
    import urllib.request

    source = _probe_source(compose)
    original = urllib.request.urlopen
    urllib.request.urlopen = _opener
    try:
        with pytest.raises(SystemExit) as stubbed:
            exec(compile(source, "<compose healthcheck>", "exec"), {})  # noqa: S102
    finally:
        urllib.request.urlopen = original
    assert stubbed.value.code == expected_exit, (
        f"probe exited {stubbed.value.code} for a {outcome} response, expected "
        f"{expected_exit}"
    )


def test_the_worker_service_names_a_runnable_module(compose) -> None:
    command = compose["services"]["worker"]["command"]
    assert command[:2] == ["python", "-m"], f"unexpected worker command {command}"
    module_path = command[2]
    module = importlib.import_module(module_path)
    assert callable(getattr(module, "main", None)), (
        f"{module_path} has no main(); `python -m {module_path}` would do nothing"
    )


def test_only_the_worker_mounts_the_databases_writable(compose) -> None:
    """The single-writer rule (絶対制約1/5), enforced at the deployment layer.

    The file's own header states the worker is the sole process that opens
    data/db/*.db for writing. A read-write mount on the api service would make
    that false in deployment however careful the code is.
    """

    assert _data_mount(compose["services"]["api"]).endswith(":ro"), (
        "the api service mounts /app/data writable — the single-writer rule is "
        "broken at the deployment layer"
    )
    assert not _data_mount(compose["services"]["worker"]).endswith(":ro"), (
        "the worker mounts /app/data read-only and could not write at all"
    )


def test_the_api_cannot_write_the_secrets_directory(compose) -> None:
    secrets = [m for m in compose["services"]["api"]["volumes"] if ":/app/secrets" in m]
    assert secrets and all(m.endswith(":ro") for m in secrets), (
        f"the api service must mount /app/secrets read-only, got {secrets}"
    )


def test_the_declared_memory_limits_fit_the_phase_1_budget(compose) -> None:
    total = sum(
        _mem_limit_mib(service["mem_limit"]) for service in compose["services"].values()
    )
    assert total < MEMORY_CEILING_MIB, (
        f"declared mem_limits total {total} MiB, over the {MEMORY_CEILING_MIB} MiB "
        "Phase-1 budget for API + worker"
    )


def test_the_deployment_is_exactly_two_containers(compose) -> None:
    """The file's header: 'exactly two containers, one writer'."""

    assert sorted(compose["services"]) == ["api", "worker"], (
        f"services are {sorted(compose['services'])}; a third container needs a "
        "design decision, not a compose edit"
    )


def test_both_services_run_the_same_image_from_the_repo_dockerfile(compose) -> None:
    images = {s["image"] for s in compose["services"].values()}
    assert len(images) == 1, f"services run different images: {images}"
    for name, service in compose["services"].items():
        dockerfile = REPO_ROOT / "ops" / Path(service["build"]["dockerfile"]).name
        assert dockerfile.is_file(), f"{name} builds from a missing {dockerfile}"
