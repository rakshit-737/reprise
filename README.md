# REPRISE

**Reconstruct the incident. Test the fix. Preserve the evidence.**

REPRISE is an evidence-bound investigation prototype for Kubernetes service-account
permission incidents. The first vertical slice is deterministic: it can load a
sanitized fixture or collect a bounded, metadata-only RBAC snapshot from an
explicit local Kubernetes context, then enumerate supported grant paths and
write an evidence-linked report.

## Current status

Implemented so far:

- bounded JSON fixture loading with content hashes;
- detection of a RoleBinding change followed by a successful named Secret read;
- native-RBAC path analysis for the supported subset documented in
  [`docs/supported-rbac.md`](docs/supported-rbac.md);
- explicit evidence claims, limitations, and coverage warnings;
- strict Pydantic evidence/proposal contracts with canonical proposal digests;
- checked-in JSON Schemas for claims, proposals, and evidence packages;
- deterministic JSON and Markdown report generation;
- a local, read-only FastAPI replay API;
- a local content-addressed artifact store that preserves accepted fixture bytes
  and normalized RBAC snapshots;
- a read-only Kubernetes RBAC snapshot adapter for an explicit kubeconfig
  context; it collects Roles, ClusterRoles, bindings, and ServiceAccount
  metadata but never requests Secrets or mutates the cluster;
- a bounded Metadata-level Kubernetes audit JSONL adapter that rejects request /
  response bodies and can replay the flagship incident offline;
- read-only `SubjectAccessReview` differential checks against the API server;
- bounded RBAC watch-history replay with bookmark and resource-version gap
  handling;
- durable local case state with guarded transitions, idempotency, and a
  hash-linked event trail;
- deterministic paired shadow validation that rejects ineffective proposals and
  checks declared benign workflows;
- exact-digest, expiring, single-use approval records (local-only; no executor
  attached);
- tests for redundant paths, `resourceNames`, and wildcard matching.

Not implemented yet: live Kubernetes audit tailing, PostgreSQL, authentication,
LLM investigation, shadow-cluster execution, or mutation. Approval records exist
locally but are not authenticated and are not connected to an executor. Those
boundaries are intentional; the project must earn them through later acceptance
gates.

## Run the demo

Requires Python 3.12+ (Python 3.14 is supported in this workspace).

```powershell
uv sync --dev
uv run python -m reprise.cli examples/fixtures/alternate-path.json --out artifacts/demo
```

The command writes:

- `artifacts/demo/evidence-package.json`
- `artifacts/demo/report.md`
- `artifacts/store/` — immutable content-addressed source and snapshot bytes

Start the local replay API:

```powershell
uv run uvicorn reprise.api:app --host 127.0.0.1 --port 8787
```

It exposes `GET /health`, `GET /v1/capabilities`, and `POST /v1/replay`.
The replay endpoint accepts only bounded metadata-only JSON fixtures and has no
mutation route. It is local development infrastructure, not a production API.

Install the optional Kubernetes adapter and capture the current RBAC metadata
from the owned kind cluster:

```powershell
uv sync --extra kubernetes
uv run --extra kubernetes reprise-snapshot `
  --context kind-reprise-demo `
  --environment-id owned-kind-reprise-demo `
  --out artifacts/live-rbac `
  --artifact-root artifacts/store
```

This writes `rbac-fixture.json`, `snapshot-summary.json`, and a read-only
evidence package/report. The capture is intentionally a snapshot only: it does
not establish that any incident occurred.

Replay a sanitized Metadata-level audit export against an RBAC fixture:

```powershell
uv run reprise-audit `
  --rbac-fixture examples/fixtures/alternate-path.json `
  --audit-log examples/fixtures/metadata-audit.jsonl `
  --out artifacts/audit-replay `
  --artifact-root artifacts/store
```

This produces the flagship finding, evidence links, and the ineffective-fix
counterexample without contacting a cluster.

Compare the deterministic model with the live API server:

```powershell
uv run --extra kubernetes reprise-sar `
  --context kind-reprise-demo `
  --principal system:serviceaccount:kube-system:bootstrap-signer `
  --verb get --resource configmaps --namespace kube-public `
  --rbac-fixture artifacts/live-rbac/rbac-fixture.json
```

Replay RBAC watch history and surface continuity gaps:

```powershell
uv run reprise-history examples/fixtures/rbac-watch.jsonl `
  --out artifacts/history/replay.json
```

Create and advance a durable local case from an evidence package:

```powershell
uv run reprise-case --db artifacts/reprise-cases.db create `
  --package artifacts/demo/evidence-package.json --case-id case:demo-replay
uv run reprise-case --db artifacts/reprise-cases.db show --case-id case:demo-replay
```

Run the flagship remediation candidates without mutating Kubernetes:

```powershell
uv run reprise-validate --fixture examples/fixtures/alternate-path.json `
  --candidate naive_first_path_only --out artifacts/validation
uv run reprise-validate --fixture examples/fixtures/alternate-path.json `
  --candidate all_supported_paths --out artifacts/validation
```

Create a local approval record from a passed validation artifact:

```powershell
uv run reprise-approve --db artifacts/approvals.db create `
  --validation artifacts/validation/all_supported_paths.json `
  --approver operator --out artifacts/approval.json
```

Run tests with:

```powershell
uv run pytest -q
```

Regenerate the public JSON Schemas after contract changes:

```powershell
uv run python scripts/export_schemas.py
```

See [`docs/implementation-plan.md`](docs/implementation-plan.md) for the
acceptance-gated roadmap and [`docs/implementation-ledger.md`](docs/implementation-ledger.md)
for the work completed in this folder.

## Safety boundary

This repository is read-only with respect to any observed environment. It does
not contain cluster credentials, does not contact public systems, and does not
execute Kubernetes mutations. Future lab execution must remain separately
enrolled, explicitly approved, and fail closed on stale state.
