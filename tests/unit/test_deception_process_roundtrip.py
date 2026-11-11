"""Opt-in separate-process Deception -> real Knowledge -> offline replay proof.

No production service, model, feed or control path is started. Missing explicit
producer source/interpreter skips this cross-repository lab, never proves it.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
PEER = Path(__file__).with_name('_deception_process_peer.py')
ENVIRONMENT = 'historical-process-roundtrip'
MAX_BYTES = 1024 * 1024
requires_producer = pytest.mark.skipif(
    not os.environ.get('AZAZEL_DECEPTION_SOURCE') or not os.environ.get('AZAZEL_DECEPTION_PYTHON'),
    reason='explicit clean Deception source and interpreter required for process lab',
)


class _NumericLoopback(http.client.HTTPConnection):
    def connect(self) -> None:
        # Avoid getaddrinfo/proxies entirely: the only destination is this
        # test's numeric loopback listener with its inherited ephemeral port.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        self.sock.connect(('127.0.0.1', self.port))


def _cleanup(process: subprocess.Popen[bytes]) -> None:
    errors: list[BaseException] = []

    def signal_group(kind: signal.Signals) -> None:
        try:
            os.killpg(process.pid, kind)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            errors.append(exc)

    try:
        alive = process.poll() is None
    except BaseException as exc:
        errors.append(exc)
        alive = True
    if alive:
        signal_group(signal.SIGTERM)
    reaped = False
    try:
        process.wait(timeout=3)
        reaped = True
    except subprocess.TimeoutExpired:
        pass
    except BaseException as exc:
        errors.append(exc)
    if not reaped:
        signal_group(signal.SIGKILL)
        try:
            process.wait(timeout=3)
        except BaseException as exc:
            errors.append(exc)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise RuntimeError(f'process cleanup failed in {len(errors)} step(s)') from errors[0]


class Lab:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.chmod(0o700)
        self.children: list[subprocess.Popen[bytes]] = []
        self.server: subprocess.Popen[bytes] | None = None
        self.port = 0
        self.logs: list[Any] = []
        self.tokens: dict[str, Any] = {}

    def spawn(self, role: str, *, fd: int | None = None) -> subprocess.Popen[bytes]:
        if role not in {'produce', 'tamper', 'prepare', 'serve', 'drain', 'readback', 'replay'}:
            raise ValueError('fixed test peer role required')
        python = os.environ['AZAZEL_DECEPTION_PYTHON'] if role in {'produce', 'tamper'} else sys.executable
        env = dict(os.environ)
        env['PYTHONPATH'] = os.pathsep.join([str(ROOT/'src'), str(ROOT/'tests/unit'), env.get('PYTHONPATH', '')])
        command = [python, str(PEER), role, str(self.root)]
        if fd is not None: command.append(str(fd))
        log = (self.root/f'peer-{len(self.children)}.stderr').open('xb')
        os.chmod(log.name, 0o600)
        self.logs.append(log)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=log, env=env, pass_fds=() if fd is None else (fd,), start_new_session=True)
        self.children.append(process)
        return process

    def call(self, role: str) -> dict[str, Any]:
        process = self.spawn(role)
        try:
            raw, _ = process.communicate(timeout=12)
            assert process.returncode == 0, f'fixed {role} peer failed; retained stderr in private lab'
            assert len(raw) <= MAX_BYTES
            value = json.loads(raw)
            assert value['pid'] == process.pid != os.getpid()
            result_path = self.root/f'result-{self.children.index(process)}-{role}.json'
            with result_path.open('xb') as artifact:
                os.chmod(result_path, 0o600)
                artifact.write(raw)
                artifact.flush()
                os.fsync(artifact.fileno())
            return value
        finally:
            _cleanup(process)

    def request(self, method: str, path: str, *, body: Any = None,
                token: str | None = None) -> tuple[int, Any]:
        assert path.startswith('/v1/') and not path.startswith('//')
        raw = None if body is None else json.dumps(body).encode()
        assert raw is None or len(raw) <= MAX_BYTES
        headers = {'Content-Type': 'application/json'}
        if token is not None: headers['Authorization'] = 'Bearer '+token
        connection = _NumericLoopback('127.0.0.1', self.port, timeout=2)
        try:
            connection.request(method, path, body=raw, headers=headers)
            response = connection.getresponse()
            received = response.read(MAX_BYTES+1)
            assert len(received) <= MAX_BYTES
            return response.status, json.loads(received)
        finally:
            connection.close()

    def start(self) -> None:
        self.tokens = self.call('prepare')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(8)
            self.port = listener.getsockname()[1]
            self.server = self.spawn('serve', fd=listener.fileno())
            deadline = time.monotonic()+10
            while time.monotonic() < deadline:
                assert self.server.poll() is None, 'real API exited before readiness'
                try:
                    status, _ = self.request('GET', '/v1/ingest/absent', token=self.tokens['ingest'])
                    if status == 404: return
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.02)
            raise AssertionError('bounded real API readiness deadline')

    def close(self) -> None:
        errors = []
        for process in reversed(self.children):
            try: _cleanup(process)
            except BaseException as exc: errors.append(exc)
        for log in self.logs:
            try: log.close()
            except BaseException as exc: errors.append(exc)
        if errors:
            raise RuntimeError(f'lab cleanup failed for {len(errors)} resource(s)') from errors[0]


@pytest.fixture
def lab(tmp_path: Path):
    value = Lab(tmp_path)
    try:
        yield value
    finally:
        value.close()
        assert all(child.poll() is not None for child in value.children)


@requires_producer
def test_actual_producer_api_drain_readback_and_offline_replay(lab: Lab) -> None:
    producer = lab.call('produce')
    payload = producer['payload']
    assert producer['clock_scope'] == 'explicit_historical_synthetic_case_not_live_traffic'
    assert len(payload['items']) == 2 and producer['source_files_sha256']
    lab.start()
    code, accepted = lab.request('POST', '/v1/deception-observations', body=payload, token=lab.tokens['ingest'])
    assert code == 202
    batch_id = accepted['batch_id']
    code, pending = lab.request('GET', '/v1/ingest/'+batch_id, token=lab.tokens['ingest'])
    assert code == 200 and pending['drained'] is False
    assert lab.call('readback')['rows'] == []  # 202 is not database persistence.
    drained = lab.call('drain')['stats']
    assert drained['lines_valid'] == 2 and drained['lines_invalid'] == 0
    code, status = lab.request('GET', '/v1/ingest/'+batch_id, token=lab.tokens['ingest'])
    assert code == 200 and status['drained'] is True and status['valid'] == 2 and status['invalid'] == []
    rows = lab.call('readback')['rows']
    assert [row['uid'] for row in rows] == [item['observation_id'] for item in payload['items']]
    assert [row['raw'] for row in rows] == payload['items']
    path = '/v1/deception-effectiveness?environment_id='+ENVIRONMENT
    code, first = lab.request('GET', path, token=lab.tokens['read'])
    code2, second = lab.request('GET', path, token=lab.tokens['read'])
    assert code == code2 == 200 and first == second
    assert first == lab.call('replay')['advisory'] == lab.call('replay')['advisory']
    assert first['authority'] == 'advisory_only' and first['executable'] is False
    assert first['observation_refs'] == [row['uid'] for row in rows]
    assert any('belief' in unknown for unknown in first['unknowns'])
    assert any('scanner_noise' in counter for counter in first['counter_evidence'])
    assert lab.call('drain')['stats']['batches_drained'] == 0
    code, _ = lab.request('POST', '/v1/deception-observations', body=payload, token=lab.tokens['ingest'])
    assert code == 202
    repeated = lab.call('drain')['stats']
    assert repeated['duplicates_skipped'] == 2
    assert lab.call('readback')['rows'] == rows
    assert lab.call('replay')['advisory'] == first


@requires_producer
def test_wrong_auth_and_scope_cannot_spool_producer_facts(lab: Lab) -> None:
    payload = lab.call('produce')['payload']
    lab.start()
    code, _ = lab.request('POST', '/v1/deception-observations', body=payload)
    assert code == 401
    code, _ = lab.request('POST', '/v1/deception-observations', body=payload, token=lab.tokens['read'])
    assert code == 403
    assert not list((lab.root/'spool').rglob('*.jsonl'))
    assert lab.call('readback')['rows'] == []


@requires_producer
def test_tampered_producer_chain_refuses_export_without_knowledge_ack(lab: Lab) -> None:
    process = lab.spawn('tamper')
    raw, _ = process.communicate(timeout=12)
    assert process.returncode != 0 and raw == b''
    assert lab.server is None and not (lab.root/'data').exists()
    assert list((lab.root/'producer').rglob('*.jsonl'))  # Preserve original tampered evidence.


@requires_producer
def test_verdict_fields_cannot_become_accepted_fact_or_advisory(lab: Lab) -> None:
    payload = lab.call('produce')['payload']
    payload['items'][0]['metadata']['attacker_believed'] = True
    lab.start()
    code, _ = lab.request('POST', '/v1/deception-observations', body=payload, token=lab.tokens['ingest'])
    assert code == 422
    assert not list((lab.root/'spool').rglob('*.jsonl'))
    assert lab.call('readback')['rows'] == []


def test_cleanup_attempts_every_group_reap_and_channel_after_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    calls: list[tuple[Any, ...]] = []

    def close(name: str, *, fail: bool = False) -> Any:
        def operation() -> None:
            calls.append(('close', name))
            if fail:
                raise OSError('injected channel close failure')
        return SimpleNamespace(close=operation)

    def peer(pid: int, *, troublesome: bool) -> Any:
        waits = 0
        def wait(*, timeout: int) -> int:
            nonlocal waits
            waits += 1
            calls.append(('wait', pid, timeout))
            if troublesome and waits == 1:
                raise subprocess.TimeoutExpired('fixed-test-peer', timeout)
            return 0
        return SimpleNamespace(pid=pid, poll=lambda: None, wait=wait,
            stdin=close(f'{pid}-stdin', fail=troublesome),
            stdout=close(f'{pid}-stdout'), stderr=close(f'{pid}-stderr'))

    def kill_group(pid: int, kind: signal.Signals) -> None:
        calls.append(('signal', pid, kind))
        if pid == 222 and kind == signal.SIGTERM:
            raise OSError('injected termination failure')

    monkeypatch.setattr(os, 'killpg', kill_group)
    value = Lab(tmp_path)
    value.children = [peer(111, troublesome=False), peer(222, troublesome=True)]
    value.logs = [close('first-log', fail=True), close('second-log')]
    with pytest.raises(RuntimeError, match='lab cleanup failed for 2 resource'):
        value.close()
    assert ('signal', 222, signal.SIGKILL) in calls
    assert calls.count(('wait', 222, 3)) == 2
    assert ('signal', 111, signal.SIGTERM) in calls and ('wait', 111, 3) in calls
    assert [call[1] for call in calls if call[0] == 'close'] == [
        '222-stdin', '222-stdout', '222-stderr',
        '111-stdin', '111-stdout', '111-stderr', 'first-log', 'second-log',
    ]
