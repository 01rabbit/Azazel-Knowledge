"""Fixed test-only peers: historical facts, real Knowledge API/drain/replay."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 1, 1, 0, 10, tzinfo=timezone.utc)
OBSERVED = datetime(2026, 1, 1, tzinfo=timezone.utc)
ENVIRONMENT = 'historical-process-roundtrip'
MAX_BYTES = 1024 * 1024


RECORDED_CASE_SHA256 = '6a66230355a24edd7b23ae6c616b845aae69aaee1427f0b3ebceb89e273ffeef'
RECORDED_PAYLOAD_SHA256 = 'b08d19856629ac9f39fb630c444b7f1f7739009cade021df73f75df57e03db61'


def load_recorded_canary(raw: bytes | None = None) -> dict[str, Any]:
    if raw is None:
        with (ROOT/'tests/fixtures/recorded_canary_v1.json').open('rb') as source:
            raw = source.read(MAX_BYTES+1)
    if len(raw) > MAX_BYTES:
        raise ValueError('recorded canary case exceeds bound')
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate recorded canary key')
            result[key] = value
        return result
    case = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite recorded canary case')))
    canonical = json.dumps(case, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if hashlib.sha256(canonical).hexdigest() != RECORDED_CASE_SHA256:
        raise ValueError('recorded canary case/clock/provenance binding mismatch')
    payload = json.dumps(case['payload'], sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if hashlib.sha256(payload).hexdigest() != case['payload_sha256'] or case['payload_sha256'] != RECORDED_PAYLOAD_SHA256:
        raise ValueError('recorded canary payload binding mismatch')
    observed = datetime.fromisoformat(case['payload']['items'][0]['observed_at'].replace('Z', '+00:00'))
    query = datetime.fromisoformat(case['query_as_of'])
    if query != observed + timedelta(seconds=60):
        raise ValueError('recorded canary clock relation mismatch')
    return case


def process_context(profile: str | None = None) -> tuple[str, datetime]:
    selected = profile if profile is not None else os.environ.get('AZAZEL_KNOWLEDGE_TEST_PROFILE', 'historical')
    if selected == 'historical':
        return ENVIRONMENT, NOW
    if selected == 'recorded-canary-v1':
        case = load_recorded_canary()
        return case['payload']['environment_id'], datetime.fromisoformat(case['query_as_of'])
    raise ValueError('unknown fixed process test profile')


def emit(value: Any) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(raw.encode()) > MAX_BYTES:
        raise ValueError('test peer result exceeds bound')
    print(raw, flush=True)


def produce(root: Path, *, tamper: bool) -> None:
    source = Path(os.environ['AZAZEL_DECEPTION_SOURCE']).resolve()
    sys.path.insert(0, str(source / 'src'))
    from azazel_deception.runtime.observation import InteractionObserver
    from azazel_deception.runtime.observation_export import export_observations
    from azazel_deception.runtime.state import RuntimeStateStore

    state_root = root / 'producer'
    state_root.mkdir(mode=0o700)
    state = RuntimeStateStore(state_root)
    observer = InteractionObserver(state, environment_id=ENVIRONMENT,
        package_id='historical-synthetic-package', node_id='historical-synthetic-node')
    observer.record(observation_class='interaction', surface='port', observed_at=OBSERVED)
    observer.record(observation_class='reaction', surface='service', reaction_kind='enumerate',
        observed_at=OBSERVED, dwell_ms=3000, attempt_count=2,
        confounder_tags=['scanner_noise'], evidence_refs=['evidence:historical:process'])
    evidence = state.evidence_path(ENVIRONMENT)
    if tamper:
        raw = evidence.read_text()
        evidence.write_text(raw.replace('"attempt_count": 2', '"attempt_count": 3'))
    if not state.verify_evidence_chain(ENVIRONMENT):
        raise ValueError('historical producer chain failed verification; no export')
    exported = export_observations(state, ENVIRONMENT)
    payload = dict(environment_id=ENVIRONMENT, items=exported)
    emit(dict(pid=os.getpid(), payload=payload,
        evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
        source_files_sha256={name: hashlib.sha256((source/'src/azazel_deception/runtime'/name).read_bytes()).hexdigest()
                             for name in ('observation.py', 'observation_export.py', 'state.py')},
        installed_fabric_distribution_version=version('azazel-fabric'),
        loaded_fabric_contracts_sha256=hashlib.sha256(
            Path(sys.modules['azazel_fabric.deception_contracts'].__file__).read_bytes()).hexdigest(),
        clock_scope='explicit_historical_synthetic_case_not_live_traffic'))


def prepare(root: Path) -> None:
    from _api_support import make_local_db, make_intel_generation, add_api_client
    make_local_db(root/'data/local.db')
    make_intel_generation(root/'data/db')
    emit(dict(pid=os.getpid(), ingest=add_api_client(root/'data/local.db', 'process-ingest', ['ingest']),
              read=add_api_client(root/'data/local.db', 'process-read', ['read'])))


def serve(root: Path, fd: int) -> None:
    import uvicorn
    from azazel_knowledge.api.app import Settings, create_app
    from azazel_knowledge.core.clock import FixedClock
    settings = Settings(config_dir=ROOT/'config', local_db_path=root/'data/local.db',
        data_db_dir=root/'data/db', spool_root=root/'spool', audit_dir=root/'audit',
        clock=FixedClock(process_context()[1]), proc_id='historical-process-api', boot_id='historical-process-boot')
    app = create_app(settings)
    # Existing routes only. PID is recorded from the actual Popen, not a fake API ack.
    channel = socket.socket(fileno=fd)
    if channel.getsockname()[0] != '127.0.0.1':
        raise ValueError('test server requires numeric loopback')
    config = uvicorn.Config(app, host='127.0.0.1', port=0, log_level='error',
                            access_log=False, timeout_graceful_shutdown=2)
    uvicorn.Server(config).run(sockets=[channel])


def drain(root: Path) -> None:
    from azazel_knowledge.core.clock import FixedClock
    from azazel_knowledge.db.writer import PrioritySingleWriterQueue
    from azazel_knowledge.ingest.drain import drain_endpoint
    from azazel_knowledge.ingest.spool import SpoolWriter
    writer = PrioritySingleWriterQueue(root/'data/local.db', root/'writer.lock')
    writer.open()
    try:
        result = drain_endpoint('deception-observations', SpoolWriter(root/'spool'), writer,
                                clock=FixedClock(process_context()[1]))
        emit(dict(pid=os.getpid(), stats=asdict(result)))
    finally:
        writer.close()


def readback(root: Path, *, replay: bool) -> None:
    from azazel_knowledge.core.config import TrackedConfigLoader
    from azazel_knowledge.correlate.deception_effectiveness import summarize_effectiveness
    from azazel_knowledge.api.contracts import build_effectiveness_advisory
    import subprocess
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError('offline readback/replay cannot launch processes or sockets')
    socket.socket = forbidden  # type: ignore[assignment]
    subprocess.Popen = forbidden  # type: ignore[assignment,misc]
    conn = sqlite3.connect((root/'data/local.db').resolve().as_uri()+'?mode=ro', uri=True)
    conn.execute('PRAGMA query_only=ON')
    try:
        if replay:
            loader = TrackedConfigLoader(ROOT/'config')
            environment, query_as_of = process_context()
            summary = summarize_effectiveness(conn, environment_id=environment, package_id=None,
                config=loader.deception_effectiveness(), query_as_of=query_as_of, config_hash=loader.config_hash)
            emit(dict(pid=os.getpid(), advisory=build_effectiveness_advisory(summary.advisory)))
        else:
            rows = conn.execute('SELECT observation_uid, raw FROM deception_observation ORDER BY observation_uid').fetchall()
            emit(dict(pid=os.getpid(), rows=[dict(uid=uid, raw=json.loads(raw)) for uid, raw in rows]))
    finally:
        conn.close()


def main() -> None:
    if len(sys.argv) not in (3, 4):
        raise ValueError('fixed test peer arguments required')
    role, root = sys.argv[1], Path(sys.argv[2])
    process_context()  # Validate a recorded profile before bootstrap or any socket.
    if os.environ.get('AZAZEL_KNOWLEDGE_TEST_PROFILE', 'historical') != 'historical' and role in {'produce', 'tamper'}:
        raise ValueError('recorded profile never generates a new Deception observation')
    if role == 'produce': produce(root, tamper=False)
    elif role == 'tamper': produce(root, tamper=True)
    elif role == 'prepare': prepare(root)
    elif role == 'serve' and len(sys.argv) == 4: serve(root, int(sys.argv[3]))
    elif role == 'drain': drain(root)
    elif role == 'readback': readback(root, replay=False)
    elif role == 'replay': readback(root, replay=True)
    else: raise ValueError('unknown fixed test role')


if __name__ == '__main__':
    main()
