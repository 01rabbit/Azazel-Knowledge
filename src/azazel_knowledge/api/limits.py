"""Request body/quota caps for the API layer (design F-10).

Pure constants and small pure checks -- no framework imports, so they
are trivial to unit test and to reuse from both routers and tests.
"""

from __future__ import annotations

CONTEXT_MAX_BODY_BYTES = 256 * 1024
CONTEXT_MAX_ENTITIES = 64

INGEST_LINE_MAX_BYTES = 64 * 1024
INGEST_BATCH_MAX_BYTES = 8 * 1024 * 1024
INGEST_DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024
INGEST_QUOTA_RETRY_AFTER_S = 30
# A feedback bundle yields one (outcome, effect_observation) pair; a batch is a
# handful of environments' worth, not a replay of history.
INGEST_OUTCOME_ENVELOPE_MAX_ITEMS = 64

WARMUP_RETRY_AFTER_S = 5


class ContextRequestTooLarge(Exception):
    """Raised when a `/v1/context` body exceeds `CONTEXT_MAX_BODY_BYTES`."""


class IngestBatchTooLarge(Exception):
    """Raised when a single ingest request body exceeds `INGEST_BATCH_MAX_BYTES`."""


def check_context_body_size(body: bytes) -> None:
    if len(body) > CONTEXT_MAX_BODY_BYTES:
        raise ContextRequestTooLarge(
            f"{len(body)} bytes exceeds cap {CONTEXT_MAX_BODY_BYTES}"
        )


def check_ingest_batch_size(body: bytes) -> None:
    if len(body) > INGEST_BATCH_MAX_BYTES:
        raise IngestBatchTooLarge(
            f"{len(body)} bytes exceeds cap {INGEST_BATCH_MAX_BYTES}"
        )
