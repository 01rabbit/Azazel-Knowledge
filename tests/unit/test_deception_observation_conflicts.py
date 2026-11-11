"""Changed-content observation IDs quarantine at the existing worker boundary."""
from __future__ import annotations

import copy
import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterator

import pytest

from _api_support import QUERY_AS_OF, add_api_client, auth_header, make_client
from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.db.writer import PrioritySingleWriterQueue
from azazel_knowledge.ingest.drain import drain_endpoint
from azazel_knowledge.ingest.spool import SpoolWriter

ENDPOINT = 'deception-observations'
ERROR = 'observation_id already stored with different content'


def observation(uid: str = 'observation-1') -> dict[str, Any]:
    return dict(observation_id=uid, environment_id='environment-1', package_id='package-1',
        node_id='node-1', observed_at=QUERY_AS_OF.isoformat(), observation_class='reaction',
        surface='service', reaction_kind='enumerate', dwell_ms=3000,
        evidence_refs=['evidence:source-1'], confounder_tags=['scanner_noise'],
        runtime_context=dict(selected_tier='lite', architecture='arm64', runtime_adapter='docker_compose',
                             active_components=['web'], omitted_components=[]),
        metadata=dict(edge_id='edge-1', actor_key='opaque-actor', package_sha256='a'*64,
                      limitations='reported source context remains unverified'))


class Ingest:
    def __init__(self, client: Any, settings: Any, root: Path, ingest: str, read: str) -> None:
        self.client, self.settings, self.root = client, settings, root
        self.ingest, self.read = ingest, read
        self.spool = SpoolWriter(settings.spool_root)

    def drain(self) -> Any:
        writer = PrioritySingleWriterQueue(self.settings.local_db_path, self.root/'writer.lock')
        writer.open()
        try:
            return drain_endpoint(ENDPOINT, self.spool, writer, clock=FixedClock(QUERY_AS_OF))
        finally:
            writer.close()

    def submit(self, lines: list[str]) -> tuple[str, Any, dict[str, Any]]:
        response = self.client.post('/v1/'+ENDPOINT, content=('\n'.join(lines)+'\n').encode(),
                                    headers=auth_header(self.ingest))
        assert response.status_code == 202
        batch_id = response.json()['batch_id']
        stats = self.drain()
        status = self.client.get('/v1/ingest/'+batch_id, headers=auth_header(self.ingest))
        assert status.status_code == 200
        return batch_id, stats, status.json()

    def rows(self) -> list[tuple[Any, ...]]:
        with sqlite3.connect(self.settings.local_db_path.resolve().as_uri()+'?mode=ro', uri=True) as conn:
            return conn.execute('SELECT * FROM deception_observation ORDER BY observation_uid').fetchall()

    def advisory(self) -> dict[str, Any]:
        response = self.client.get('/v1/deception-effectiveness?environment_id=environment-1',
                                   headers=auth_header(self.read))
        assert response.status_code == 200
        return response.json()

    def retained_lines(self, batch_id: str) -> list[str]:
        return (self.settings.spool_root/ENDPOINT/'drained'/(batch_id+'.jsonl')).read_text().splitlines()


@pytest.fixture
def ingest(tmp_path: Path) -> Iterator[Ingest]:
    client, settings, local, _ = make_client(tmp_path)
    token = add_api_client(local, 'test-ingest', ['ingest'])
    reader = add_api_client(local, 'test-reader', ['read'])
    with client:
        yield Ingest(client, settings, tmp_path, token, reader)


def test_identical_content_deduplicates_across_serialization_and_redrain(ingest: Ingest) -> None:
    fact = observation()
    _, first, _ = ingest.submit([json.dumps(fact)])
    rows, advisory = ingest.rows(), ingest.advisory()
    reordered = dict(reversed(list(fact.items())))
    batch, stats, status = ingest.submit([json.dumps(reordered, separators=(',', ':'))])
    assert first.lines_valid == 1 and stats.lines_valid == 1
    assert stats.duplicates_skipped == 1 and stats.lines_invalid == 0
    assert status['valid'] == 1 and status['invalid'] == [] and status['drained'] is True
    assert ingest.rows() == rows and ingest.advisory() == advisory
    assert json.loads(ingest.retained_lines(batch)[0]) == fact
    assert ingest.drain().batches_drained == 0
    assert ingest.rows() == rows


@pytest.mark.parametrize('changed', ['metric', 'runtime_context', 'provenance', 'evidence_refs',
                                    'environment', 'node', 'observed_at'])
def test_changed_content_identity_is_rejected_not_duplicate_or_overwritten(ingest: Ingest, changed: str) -> None:
    first = observation()
    ingest.submit([json.dumps(first)])
    rows, advisory = ingest.rows(), ingest.advisory()
    other = copy.deepcopy(first)
    if changed == 'metric': other['dwell_ms'] = 99999
    elif changed == 'runtime_context': other['runtime_context']['architecture'] = 'amd64'
    elif changed == 'provenance': other['metadata']['package_sha256'] = 'b'*64
    elif changed == 'evidence_refs': other['evidence_refs'] = ['evidence:other-source']
    elif changed == 'environment': other['environment_id'] = 'unrelated-environment'
    elif changed == 'node': other['node_id'] = 'unrelated-producer'
    elif changed == 'observed_at': other['observed_at'] = (QUERY_AS_OF+timedelta(seconds=1)).isoformat()
    batch, stats, status = ingest.submit([json.dumps(other)])
    assert stats.lines_valid == 0 and stats.lines_invalid == 1 and stats.duplicates_skipped == 0
    assert status['valid'] == 0 and status['invalid'] == [dict(line_no=1, error=ERROR)]
    assert status['drained'] is True
    assert ingest.rows() == rows and ingest.advisory() == advisory
    assert json.loads(ingest.retained_lines(batch)[0]) == other
    assert ingest.drain().batches_drained == 0
    assert ingest.rows() == rows


def test_mixed_batch_keeps_original_line_numbers_and_accepts_unrelated_facts(ingest: Ingest) -> None:
    first = observation()
    ingest.submit([json.dumps(first)])
    original = ingest.rows()[0]
    conflict = copy.deepcopy(first)
    conflict['metadata']['limitations'] = 'different source statement'
    good = observation('observation-2')
    lines = ['not json', json.dumps(first), json.dumps(conflict), json.dumps(good)]
    batch, stats, status = ingest.submit(lines)
    assert (stats.lines_valid, stats.lines_invalid, stats.duplicates_skipped) == (2, 2, 1)
    assert status['line_count'] == 4 and status['valid'] == 2
    assert [item['line_no'] for item in status['invalid']] == [1, 3]
    assert status['invalid'][1]['error'] == ERROR
    rows = ingest.rows()
    assert len(rows) == 2 and rows[0] == original
    assert ingest.advisory()['observation_refs'] == ['observation-1', 'observation-2']
    assert ingest.retained_lines(batch) == lines


def test_conflicting_same_batch_identity_keeps_first_fact_and_exact_repeat(ingest: Ingest) -> None:
    first = observation()
    other = copy.deepcopy(first)
    other['evidence_refs'] = ['evidence:conflicting-statement']
    _, stats, status = ingest.submit([json.dumps(first), json.dumps(other), json.dumps(first)])
    assert (stats.lines_valid, stats.lines_invalid, stats.duplicates_skipped) == (2, 1, 1)
    assert status['invalid'] == [dict(line_no=2, error=ERROR)]
    with sqlite3.connect(ingest.settings.local_db_path.resolve().as_uri()+'?mode=ro', uri=True) as conn:
        raw = conn.execute('SELECT raw FROM deception_observation').fetchall()
    assert len(raw) == 1 and json.loads(raw[0][0]) == first
