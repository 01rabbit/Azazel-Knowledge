# Contributing to Azazel-Knowledge

This is an advisory-only, deterministic CTI node. It never commands — final
authority always stays with the Azazel-Edge deterministic arbiter. Every
contribution is judged against that one rule first.

## Before you start

- Read `CLAUDE.md` — the commander/adversarial-review charter and the eight
  absolute constraints. They are binding, not guidance.
- Read `AGENTS.md` if you are implementing under delegation; it defines the
  implementer's operating envelope.
- `docs/design/phase1-implementation.md` items F-1..F-20 are settled
  decisions. Do not silently contradict them in code.
- Every `docs/adr/*` decision is settled. Overturning one requires a new ADR
  in the same PR, not a quiet code change.

## Branch naming

`<type>/<short-description>`, e.g. `fix/audit-chain-replay`,
`feat/taxii-collection-filter`.

## Commit message format

`<type>(<scope>): <summary>`

Scopes: `api`, `scoring`, `correlate`, `feeds`, `ingest`, `bundle`, `audit`,
`attack`, `recommend`, `taxii`, `worker`, `docs`, `ops`.

## Pull request rules

- 1 PR = 1 purpose.
- `python -m pytest tests/unit -q` passes; test count never decreases
  (current baseline: 591).
- `python azctl check-config --config-dir config` passes.
- `python tools/docs-sync-check.py` passes.
- If behavior or a contract changes, the relevant docs (`docs/api.md`,
  `docs/scoring.md`, `docs/data-model.md`, ADRs, ...) are revised in the
  **same PR** — never left to silently diverge.
- New dependencies are forbidden without a `pyproject.toml` change plus a
  new ADR justifying the addition (absolute constraint 7).
- No wall-clock reads, randomness, or environment-dependence in `scoring/`
  or `correlate/`; time flows through `core/clock.py`'s `query_as_of` only.

## What not to do

- No write SQL (INSERT/UPDATE/DELETE/executemany) in `api/` or `taxii/` —
  writes go through the worker's single writer only; statically enforced by
  `tests/unit/test_api_static.py`.
- No partial results on error paths. Fail closed: `503 context_timeout` on
  timeout, `503 audit_unavailable` on audit-chain write failure.
- No destructive change to local-tier tables (`reaction`, `observation`,
  `advisory_log`). `reaction` is INSERT-only, enforced by a DB trigger.
- Generated Suricata/Sigma rules stay drafts. Never add a deploy path
  (ADR-0007).

## Testing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[api,dev]"
python -m pytest tests/unit -q
python azctl check-config --config-dir config
python tools/docs-sync-check.py
```

## License

Contributions are accepted under the project's MIT license (`LICENSE`).
