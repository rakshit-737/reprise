# REPRISE contributor instructions

## Non-negotiable safety invariants

1. Never treat an LLM narrative as authorization truth.
2. Never ingest Secret contents, tokens, or audit request/response bodies in the
   default profile.
3. Keep observed events, derived RBAC paths, hypotheses, and unknowns distinct.
4. Unsupported Kubernetes authorization semantics must produce an incomplete
   result, never a false denial or proof of safety.
5. Production mode is read-only. Any future mutation is limited to an enrolled
   owned lab and requires exact human approval, freshness checks, and post-change
   verification.
6. Do not add arbitrary shell, SQL, URL-fetching, or raw Kubernetes tools to the
   investigator.
7. Do not store credentials or real sensitive data in fixtures, logs, tests, or
   reports.

## Development rules

- Work in one coherent vertical slice at a time.
- Read the relevant code and tests before editing.
- Add a failing or characterization test before changing security semantics.
- Prefer small typed modules and deterministic functions.
- Preserve provenance and content hashes for evidence-bearing artifacts.
- Run the smallest meaningful test after each change, then the full focused suite.
- Update `docs/implementation-ledger.md` after a completed slice.
- Do not claim live-cluster, LLM, approval, or execution behavior until it exists
  and has an acceptance test.

## Commands

```powershell
uv sync --dev
uv run pytest -q
uv run python -m reprise.cli examples/fixtures/alternate-path.json --out artifacts/demo
```

## Module boundaries for the first slice

- `src/reprise/models.py`: immutable-ish data contracts and JSON conversion.
- `src/reprise/fixture.py`: bounded fixture parsing and artifact hashing.
- `src/reprise/rbac.py`: pure supported-RBAC matching and path enumeration.
- `src/reprise/detect.py`: deterministic incident sequence detection.
- `src/reprise/report.py`: evidence package and Markdown rendering.
- `src/reprise/cli.py`: orchestration only; no authorization semantics.
- `src/reprise/contracts.py`: strict claim/proposal/package contracts and digests.
- `src/reprise/api.py`: local-only, read-only replay API; never add mutation here.
- `src/reprise/kubernetes_adapter.py`: explicit-context, metadata-only live RBAC snapshot; never add Secret or mutation calls.
- `src/reprise/k8s_cli.py`: snapshot orchestration and output only.
- `src/reprise/audit_adapter.py`: bounded Metadata-level JSONL normalization; reject bodies and never tail arbitrary paths from an investigator.
- `src/reprise/audit_cli.py`: explicit replay orchestration only.
- `src/reprise/sar.py`: one explicit-context SubjectAccessReview and model comparison; no RBAC mutation calls.
- `src/reprise/resource_history.py`: bounded watch replay with explicit continuity gaps.
- `src/reprise/case_store.py`: local SQLite case state, guarded transitions, and hash-linked events.
- `src/reprise/case_cli.py`: case-store orchestration only; validate evidence packages before case creation.
- `src/reprise/validator.py`: deterministic virtual proposal validation; never call cluster mutation APIs.
- `src/reprise/validation_cli.py`: shadow-validation orchestration and result output only.
- `src/reprise/approval.py`: exact-digest local approval records; never add executor calls here.
- `src/reprise/approval_cli.py`: local approval-record orchestration only; not human authentication.
