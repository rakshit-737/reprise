# Durable case state

`reprise.case_store.CaseStore` is the local development implementation of
REPRISE's durable case coordinator. It uses SQLite and is deliberately separate
from the unauthenticated replay API.

## Guarantees

- explicit state-machine transitions;
- optimistic compare-and-swap using a case version;
- idempotent transition requests;
- append-only case events;
- SHA-256 hash chaining across the event sequence;
- rejection of Secret/token/request-body fields in case metadata;
- durable reopen/read verification after process restart.

The state machine is intentionally conservative. A stale transition fails rather
than overwriting a newer investigation result. A terminal state cannot be
reopened without a future explicit transition design.

## CLI

Create a case from a validated evidence package:

```powershell
uv run reprise-case --db artifacts/reprise-cases.db create `
  --package artifacts/demo/evidence-package.json `
  --case-id case:demo-replay
```

Advance it with an expected version and idempotency key:

```powershell
uv run reprise-case --db artifacts/reprise-cases.db transition `
  --case-id case:demo-replay --expected-version 0 `
  --to investigating --actor operator `
  --reason "open bounded investigation" `
  --idempotency-key transition:investigate
```

Inspect and verify the chain:

```powershell
uv run reprise-case --db artifacts/reprise-cases.db show --case-id case:demo-replay
```

This is local durable state, not a production database or an authorization
boundary. PostgreSQL, authentication, role-separated approval, and backup/
retention policy remain future phases.
