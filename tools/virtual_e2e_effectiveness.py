#!/usr/bin/env python3
"""Virtual dev end-to-end harness: Deception -> Edge -> Knowledge, on localhost.

Drives the full effectiveness loop across all three real codebases with a live
Azazel-Knowledge API on 127.0.0.1, proving the interlock in a development
environment (no containers, no attacker, no production):

  1. AZ-06 Deception records fact-only InteractionObservations to its evidence
     chain (real InteractionObserver) and exports them (real export_observations).
  2. Edge relays the observation batch to Knowledge as untrusted content
     (real KnowledgeIngestClient -> POST /v1/deception-observations).
  3. Knowledge spools the batch, the single-writer worker drains it into the
     immutable deception_observation table (real app + real `worker --once`).
  4. Knowledge computes a deterministic EffectivenessAdvisory.
  5. Edge reads and fail-closed-verifies the advisory (real
     EffectivenessAdvisoryReader -> GET /v1/deception-effectiveness).

Requires the four sibling repos importable (editable installs) plus Fabric
v0.6.0 and the Knowledge api extra (fastapi/uvicorn/pydantic). This is a dev
harness, not a CI test: no single repo's CI installs all three packages.

Run:  python tools/virtual_e2e_effectiveness.py
Exit code 0 and a printed advisory means the loop is interlocked.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

KNOWLEDGE_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = KNOWLEDGE_ROOT / "config"
ENV_ID = "env-virtual-e2e"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, cwd=str(KNOWLEDGE_ROOT), env=env, text=True,
        capture_output=True, timeout=120, check=True,
    )


def _wait_http(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.getcode() < 500:
                    return
        except urllib.error.HTTPError as exc:
            # Any HTTP status (even 401/404) proves the server is up and routing.
            if exc.code < 500:
                return
            last = exc
        except Exception as exc:  # noqa: BLE001 - dev harness liveness probe
            last = exc
        time.sleep(0.3)
    raise RuntimeError(f"server never became ready at {url}: {last}")


def _build_observations(state_root: Path) -> list[dict]:
    """AZ-06 side: record real fact-only observations and export them."""
    from azazel_deception.runtime.observation import (
        InteractionObserver,
        build_runtime_context,
    )
    from azazel_deception.runtime.observation_export import export_observations
    from azazel_deception.runtime.state import RuntimeStateStore
    from azazel_fabric.deception_contracts import PlacementPlan
    from azazel_deception.planner import build_placement_plan
    from azazel_deception.package import load_package, parse_package

    raw = load_package(
        Path("/home/user/Azazel-Deception/examples/packages/municipal-linux-v1/package.yaml")
    )
    package = parse_package(raw)
    host = {
        "node_id": "az06-e2e", "architecture": "amd64", "cpu_cores": 4,
        "memory_mb": 8192, "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False, "gpu_available": False,
    }
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, host, requested_tier="lite", edge_decision_id="edge-e2e-1")
    )
    state = RuntimeStateStore(state_root)
    observer = InteractionObserver(
        state, environment_id=ENV_ID, package_id=package.package_id,
        node_id=plan.node_id, runtime_context=build_runtime_context(package, plan),
    )
    # A small attacker episode: contact -> reaction -> outcome, plus a
    # scanner-noise confounder that Knowledge must subtract.
    observer.record(observation_class="interaction", surface="port")
    observer.record(
        observation_class="reaction", surface="credential_lure",
        reaction_kind="authenticate", lure_id="lure-municipal-admin",
        first_contact_latency_ms=900, attempt_count=2,
    )
    observer.record(
        observation_class="outcome", surface="file", reaction_kind="exfiltrate",
        dwell_ms=42000, attempt_count=4,
    )
    observer.record(
        observation_class="interaction", surface="port",
        confounder_tags=["scanner_noise"],
    )
    return export_observations(state, ENV_ID)


def main() -> int:
    env = dict(os.environ)
    root = Path(tempfile.mkdtemp(prefix="az-e2e-"))
    env["AZAZEL_ROOT"] = str(root)
    env["AZAZEL_CONFIG_DIR"] = str(CONFIG_DIR)

    print(f"[harness] provisioning Knowledge node at {root}")
    _run([sys.executable, "azctl", "provision", "--root", str(root), "--config-dir", str(CONFIG_DIR)], env=env)
    added = _run(
        [sys.executable, "azctl", "client", "add", "--root", str(root),
         "--config-dir", str(CONFIG_DIR), "--key-id", "edge1", "--scopes", "ingest,read"],
        env=env,
    )
    m = re.search(r"token.*?:\s*(azcti_\S+)", added.stdout)
    if not m:
        print("[harness] FAILED to parse client token:\n" + added.stdout, file=sys.stderr)
        return 2
    token = m.group(1)
    print("[harness] minted edge client token")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    app_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "azazel_knowledge.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(KNOWLEDGE_ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _wait_http(f"{base_url}/v1/health")
        print(f"[harness] Knowledge API live at {base_url}")

        # 1) AZ-06 Deception: record + export fact-only observations.
        with tempfile.TemporaryDirectory(prefix="az06-state-") as dstate:
            observations = _build_observations(Path(dstate))
        print(f"[harness] AZ-06 exported {len(observations)} fact-only observations")

        # 2) Edge relays them to Knowledge as untrusted content.
        from azazel_edge.deception_effectiveness_client import (
            KnowledgeAuthConfig,
            KnowledgeIngestClient,
            EffectivenessAdvisoryReader,
        )

        auth = KnowledgeAuthConfig(token=token)
        ingest = KnowledgeIngestClient(base_url, edge_node_id="edge-e2e", auth=auth)
        relay = ingest.submit_observations(observations)
        print(f"[harness] Edge relay status={relay.status} submitted={relay.submitted_count}")
        if relay.status not in {"accepted", "backpressure"}:
            print(f"[harness] relay did not succeed: {relay}", file=sys.stderr)
            return 3

        # 3) Knowledge single-writer worker drains the spool once.
        _run([sys.executable, "-m", "azazel_knowledge.worker", "--root", str(root),
              "--config-dir", str(CONFIG_DIR), "--once"], env=env)
        print("[harness] Knowledge worker drained the ingest spool")

        # 4+5) Edge reads and fail-closed-verifies the advisory.
        reader = EffectivenessAdvisoryReader(base_url, auth=auth)
        result = reader.get_advisory(ENV_ID)
        if result.advisory is None:
            print(f"[harness] no advisory available (reason={result.reason})", file=sys.stderr)
            return 4

        adv = result.advisory
        print("\n[harness] ===== EffectivenessAdvisory (advisory-only) =====")
        print(json.dumps(adv, indent=2, ensure_ascii=False))
        print("[harness] ==================================================\n")

        # Assert the loop's doctrine invariants held end-to-end.
        assert adv["authority"] == "advisory_only", adv["authority"]
        assert adv["executable"] is False
        assert adv["environment_id"] == ENV_ID
        assert 0.0 <= adv["confidence"] <= 1.0
        # The scanner-noise confounder we injected must surface as counter-evidence.
        assert adv["counter_evidence"], "expected confounder counter-evidence"
        print("[harness] OK — Deception -> Edge -> Knowledge -> advisory interlocked; "
              "advisory-only, non-executable, confounder-aware.")
        return 0
    finally:
        app_proc.terminate()
        try:
            app_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app_proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
