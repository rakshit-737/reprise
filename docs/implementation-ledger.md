# Implementation ledger

## 2026-09-27 — Initial deterministic vertical slice

### Completed

- Confirmed `D:\Academics\reprise` is accessible and initially empty.
- Preserved the supplied project brief at `reprise.md`.
- Added repository safety and contributor guidance.
- Implemented offline fixture loading with size limits and SHA-256 artifact IDs.
- Implemented deterministic suspicious-sequence detection.
- Implemented supported native-RBAC path enumeration, including two independent
  RoleBinding paths, wildcards, and `resourceNames`.
- Implemented JSON and Markdown evidence-package output.
- Added focused tests and a sanitized alternate-path demo fixture.

### Validation

- `uv run ruff format --check src tests` — passed.
- `uv run ruff check src tests` — passed.
- `uv run pytest -q` — passed: 24 tests.
- `uv run python -m reprise.cli examples/fixtures/alternate-path.json --out artifacts/demo`
  — passed; found one incident and two supported paths.

### Deliberate limitations

- No live Kubernetes access or historical watch reconstruction.
- No PostgreSQL, API authentication, LLM, shadow cluster, approval, or mutation.
- Only the supported model in `docs/supported-rbac.md` is analyzed.

### Next work

Build a durable content-addressed artifact repository and typed case state,
then add tests for incomplete evidence and unsupported RBAC semantics.

## 2026-09-27 — Contracts and replay API upgrade

### Completed

- Added strict Pydantic contracts for claims, artifacts, proposals, security
  objectives, benign invariants, and evidence packages.
- Added canonical SHA-256 proposal digests and validation of evidence references,
  environment boundaries, unique mutation targets, and counterexample effects.
- Added generated schemas under `schemas/` and a repeatable exporter at
  `scripts/export_schemas.py`.
- Added a bounded, local-only FastAPI replay API with health and capability
  endpoints; it exposes no mutation route and rejects sensitive fixture fields.
- Installed runtime dependencies `fastapi` and `uvicorn`; installed `httpx` for
  async ASGI tests.

### Validation

- `uv run pytest -q` — passed: 36 tests.
- `uv run python scripts/export_schemas.py` — passed.
- Replay output is validated before the CLI or API returns it.

### Deliberate limitations

- API authentication is not implemented and the server must remain loopback-only.
- No live Kubernetes, PostgreSQL, LLM, approval, or mutation capability exists.
- Proposal validation is static; it is not a shadow-cluster validation result.

### Superseded next work

The artifact-store portion was completed in the subsequent ledger entry; durable
case records remain future work.

## 2026-09-28 — Live read-only RBAC snapshot adapter

### Completed

- Confirmed Docker Desktop's Linux engine is running and the owned
  `kind-reprise-demo` control-plane node is Ready.
- Installed the optional official Kubernetes Python client (`kubernetes==36.0.3`).
- Added an explicit-context, bounded, read-only Kubernetes RBAC adapter for Roles,
  ClusterRoles, RoleBindings, ClusterRoleBindings, and ServiceAccount metadata.
- Excluded Secret objects, token references, labels, annotations, and arbitrary
  resources from collection.
- Added pagination limits, server fingerprint provenance, nonResourceURLs coverage
  gaps, and a dedicated `reprise-snapshot` command.
- Added converter, pagination, safety, and fake-client tests.

### Live validation

Command:

```powershell
uv run --extra kubernetes reprise-snapshot --context kind-reprise-demo --environment-id owned-kind-reprise-demo --out artifacts/live-rbac --artifact-root artifacts/store
```

Result: passed. The snapshot contained 12 Roles, 77 ClusterRoles, 12
RoleBindings, 64 ClusterRoleBindings, and 49 ServiceAccounts. It produced zero
findings because this adapter intentionally does not collect audit events.

Outputs:

- `artifacts/live-rbac/rbac-fixture.json`
- `artifacts/live-rbac/snapshot-summary.json`
- `artifacts/live-rbac/evidence-package.json`
- `artifacts/live-rbac/report.md`

### Validation

- `uv run ruff format --check src tests` — passed.
- `uv run ruff check src tests` — passed.
- `uv run pytest -q` — passed: 47 tests.
- Local kind snapshot command — passed against `kind-reprise-demo`.

### Deliberate limitations

- Audit ingestion and resource watch history are not implemented, so no live
  incident can be reconstructed yet.
- A live kubeconfig context is trusted local operator input; production
  authentication and environment enrollment do not exist yet.
- Non-resource URL rules are excluded and explicitly recorded as gaps.

### Superseded next work

The metadata-only audit replay portion was completed in the subsequent ledger
entry; live sink connectivity and resource-watch history remain future work.

## 2026-09-28 — Metadata-level audit replay adapter

### Completed

- Added bounded JSONL parsing for Kubernetes Metadata-level `AuditEvent` exports.
- Normalized only the identity, timestamp, action, object reference, and response
  status fields needed by the detector.
- Rejected request/response bodies, Secret data, duplicate keys, duplicate event
  identities, malformed timestamps, and oversized input.
- Added `reprise-audit` to merge normalized events with an accepted RBAC fixture
  and produce an evidence package.
- Added a sanitized sample at `examples/fixtures/metadata-audit.jsonl`.

### Validation

- `uv run ruff format --check src tests` — passed.
- `uv run ruff check src tests` — passed.
- `uv run pytest -q` — passed: 55 tests.
- Audit replay command — passed; reproduced one finding, two authorization paths,
  and the rejected one-binding proposal.

### Deliberate limitations

- This is replay ingestion, not live audit tailing or control-plane configuration.
- Source completeness and delivery gaps are not inferred from a JSONL file.
- A successful audit event shows API activity, not exfiltration or human identity.

### Next work

Implement versioned RBAC resource-watch ingestion and continuity-gap handling,
then run SubjectAccessReview differential checks against the owned kind cluster.

## 2026-09-28 — Differential validation and resource history

### Completed

- Added a read-only `SubjectAccessReview` client bound to an explicit kubeconfig
  context, with a structured model-vs-API comparison and mismatch exit code.
- Added bounded RBAC watch JSONL replay for Roles, ClusterRoles, bindings, and
  ServiceAccounts.
- Preserved resource versions and normalized specification digests, deduplicated
  identical replay deliveries, and surfaced bookmarks and HTTP 410 continuity
  gaps explicitly.
- Added `reprise-sar` and `reprise-history` commands plus safety tests.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 68 tests.
- Live differential check against `kind-reprise-demo` matched Kubernetes:
  `system:serviceaccount:kube-system:bootstrap-signer` was allowed to `get`
  `configmaps` in `kube-public` through the captured RoleBinding path.
- Watch replay example — passed with 2 observations, 1 bookmark, and 0 gaps.

### Deliberate limitations

- Watch collection is replay-only; a live long-running watcher and relist worker
  are not implemented yet.
- SubjectAccessReview compares current state, not historical event-time state.
- A matching SAR does not cover unsupported authorizers or indirect privilege
  paths.

### Next work

Implement a durable case/event repository and an authenticated audit sink with
continuity watermarks before connecting live incident detection.

## 2026-09-28 — Durable local case state

### Completed

- Added a SQLite-backed `CaseStore` with explicit REPRISE state-machine
  transitions and optimistic version checks.
- Added append-only case events with SHA-256 hash chaining and chain verification.
- Added idempotent transition requests and rejection of reused keys with changed
  request payloads.
- Added metadata-size limits and rejection of Secret, token, request-body, and
  response-body fields in case records.
- Added `reprise-case` CLI integration that validates an evidence package before
  creating a case and records its package digest and finding IDs.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 74 tests.
- Case smoke test — passed: created `case:demo-replay`, advanced it through
  `detected → investigating → supported`, reopened the database, and verified
  the event chain.

### Deliberate limitations

- SQLite is a local development repository, not the planned PostgreSQL service.
- The replay API does not expose case mutation endpoints and remains local-only.
- Authentication, role-separated approval, backups, retention, and multi-worker
  job leases are not implemented.

### Next work

Add a repository interface with a PostgreSQL implementation, then connect case
creation to authenticated ingestion and durable worker jobs.

## 2026-09-28 — Paired deterministic shadow validation

### Completed

- Added strict shadow-validation contracts and a checked-in
  `schemas/validation.schema.json`.
- Added deterministic virtual proposal validation for attack regression,
  declared benign workflows, exact target state, evidence completeness, and
  coverage warnings.
- Added `reprise-validate` with explicit pass/fail exit codes.
- The flagship demo now rejects `naive_first_path_only` with the surviving
  `legacy-debug-access` path and passes `all_supported_paths` while preserving
  the ConfigMap workflow.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 78 tests.
- Naive candidate — exit `3`, status `failed`, attack remained allowed.
- Corrected candidate — exit `0`, status `passed`, attack blocked and benign
  workflow passed.

### Deliberate limitations

- Shadow validation uses the deterministic fixture model and does not execute a
  Kubernetes API request or mutation.
- Passing declared workflows does not prove undisclosed application behavior.
- Live lab validation still needs a separate enrolled validation runner.

### Next work

Add a repository interface with a PostgreSQL implementation and connect shadow
validation artifacts to authenticated case transitions and durable worker jobs.

## 2026-09-28 — Exact-digest approval gateway

### Completed

- Added strict approval and validation schemas, including
  `schemas/approval.schema.json`.
- Added a local SQLite approval gateway that requires a passed validation,
  exact environment/proposal/validation digests, expiry, and a random nonce.
- Added single-use consumption with fail-closed checks for replay, wrong nonce,
  cross-environment use, digest mismatch, and expiration.
- Added `reprise-approve` CLI and kept it disconnected from Kubernetes execution.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 83 tests.
- Approval smoke test — passed: created and consumed one exact-digest approval
  for the corrected shadow-validation artifact.

### Deliberate limitations

- The local `--approver` value is not authenticated.
- SQLite approval records are not a production authorization boundary.
- No executor or cluster mutation is attached to approval consumption.

### Next work

Add authenticated identity and PostgreSQL-backed approval/case repositories,
then build a separately enrolled lab executor that accepts only consumed exact
approvals.

## 2026-09-30 — Validation and approval fail-closed hardening

### Completed

- Bound validation to the same fixture, evidence-package, finding, and proposal
  environment.
- Added an explicit snapshot-match invariant; snapshot drift now yields
  `incomplete` and cannot become an approval.
- Bound proposals to the finding principal and exact action during evidence
  package validation.
- Strengthened validation contracts so a forged `passed` behavior cannot claim a
  contradictory after-state, path list, coverage warning, or baseline.
- Required passed validations to have no counterexamples or coverage warnings.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 87 tests.
- Schema exporter — passed.
- Existing naive-fix rejection, corrected-fix pass, and exact approval smoke
  paths remain covered.

### Deliberate limitations

- These checks protect the local deterministic boundary; they do not provide
  authenticated human identity or independently immutable storage.
- Live lab execution, PostgreSQL repositories, and production change control
  remain intentionally unimplemented.

### Next work

Add authenticated identity and PostgreSQL-backed repositories, then implement a
separately enrolled lab executor with independent preflight checks.

## 2026-09-27 — Content-addressed evidence persistence

### Completed

- Added `ArtifactStore` with path-safe kinds, atomic writes, SHA-256 addressing,
  sidecar metadata, and read-time integrity verification.
- CLI runs now persist the original accepted fixture bytes and normalized RBAC
  snapshot under `artifacts/store/` and include the source artifact reference in
  the evidence package.
- Added tests for round trips, tamper detection, traversal rejection, and source
  artifact linkage.

### Validation

- `uv run ruff format --check src tests scripts` — passed.
- `uv run ruff check src tests scripts` — passed.
- `uv run pytest -q` — passed: 40 tests.
- CLI demo — passed; persisted fixture and RBAC snapshot bytes.

### Deliberate limitations

- The artifact store is local filesystem storage, not independently immutable
  storage or PostgreSQL.
- Audit-event raw bytes are not yet collected from a live adapter.

### Next work

Add durable case records and replay verification before introducing live
Kubernetes adapters.
