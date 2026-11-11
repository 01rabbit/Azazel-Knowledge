"""Actual recorded nginx canary fact through real Knowledge process boundaries."""
from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from _deception_process_peer import load_recorded_canary, RECORDED_PAYLOAD_SHA256
from test_deception_process_roundtrip import Lab, _NumericLoopback


def test_recorded_canary_fact_preserves_raw_provenance_through_actual_knowledge(tmp_path: Path) -> None:
    case = load_recorded_canary()
    original = copy.deepcopy(case)
    payload = case['payload']
    item = payload['items'][0]
    value = Lab(tmp_path, profile='recorded-canary-v1')
    try:
        value.start()
        assert value.environment_id == payload['environment_id']
        assert value.query_as_of == datetime.fromisoformat(case['query_as_of'])
        code, accepted = value.request('POST', '/v1/deception-observations', body=payload, token=value.tokens['ingest'])
        assert code == 202
        assert value.call('readback')['rows'] == []
        stats = value.call('drain')['stats']
        assert stats['lines_valid'] == 1 and stats['lines_invalid'] == 0
        code, status = value.request('GET', '/v1/ingest/'+accepted['batch_id'], token=value.tokens['ingest'])
        assert code == 200 and status['drained'] is True and status['valid'] == 1 and status['invalid'] == []
        rows = value.call('readback')['rows']
        assert rows == [dict(uid=item['observation_id'], raw=item)]
        stored = rows[0]['raw']
        assert stored['lure_id'] == item['lure_id']
        assert stored['evidence_refs'] == ['interaction:nginx', 'presentation:nginx']
        assert stored['metadata'] == item['metadata']
        assert 'reported_unverified' in stored['metadata']['limitations']
        assert stored['runtime_context']['architecture'] == 'amd64'
        assert case['provenance']['runtime_architecture_binding'] == (
            'reported_fixture_host_metadata_not_independently_verified_actual_platform')
        assert case['provenance']['producer_fabric_identity_at_capture'] == 'not_recorded'
        assert case['provenance']['production_admission'] is False
        assert case['provenance']['hardware_acceptance'] is False
        path = '/v1/deception-effectiveness?environment_id='+value.environment_id
        code, advisory = value.request('GET', path, token=value.tokens['read'])
        assert code == 200
        assert advisory == value.call('replay')['advisory'] == value.call('replay')['advisory']
        assert advisory['authority'] == 'advisory_only' and advisory['executable'] is False
        assert advisory['observation_refs'] == [item['observation_id']]
        assert any('belief' in text for text in advisory['unknowns'])
        assert any('no measured outcome' in text for text in advisory['unknowns'])
        assert 'not asserted' in advisory['assessment']
        assert datetime.fromisoformat(advisory['produced_at'].replace('Z', '+00:00')) == value.query_as_of
        assert value.call('drain')['stats']['batches_drained'] == 0
        code, _ = value.request('POST', '/v1/deception-observations', body=payload, token=value.tokens['ingest'])
        assert code == 202
        assert value.call('drain')['stats']['duplicates_skipped'] == 1
        assert value.call('readback')['rows'] == rows
        assert value.call('replay')['advisory'] == advisory
        assert case == original and case['payload_sha256'] == RECORDED_PAYLOAD_SHA256
    finally:
        value.close()
        assert all(process.poll() is not None for process in value.children)


@pytest.mark.parametrize('field', ['payload', 'query_as_of', 'provenance'])
def test_recorded_case_tamper_refuses_before_http_or_process(
    monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    case = load_recorded_canary()
    if field == 'payload':
        case['payload']['items'][0]['lure_id'] = 'other-opaque-lure'
    elif field == 'query_as_of':
        case['query_as_of'] = '2026-11-12T08:07:40.190492+00:00'
    else:
        case['provenance']['runtime_architecture_binding'] = 'independently_verified'
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError('tampered case must fail before HTTP or any process')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(_NumericLoopback, 'connect', forbidden)
    with pytest.raises(ValueError, match='case/clock/provenance binding'):
        load_recorded_canary(json.dumps(case).encode())
