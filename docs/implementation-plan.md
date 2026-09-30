# Implementation plan

## Acceptance-gated phases

| Phase | Deliverable | Gate |
|---|---|---|
| 0 — Architecture | Scope, threat model, contracts, supported-RBAC matrix, ADRs | Unsupported behavior and execution boundaries are explicit |
| 1 — Deterministic vertical slice | Fixture → finding → RBAC paths → evidence-linked report | Offline demo and focused tests pass |
| 2 — Core infrastructure | PostgreSQL schema, artifact store, API, durable jobs | Restart-safe authenticated read-only API |
| 3 — Kubernetes adapters | Audit ingestion and RBAC resource history | Differential tests against a local API server |
| 4 — Evidence contracts | Claim schemas, validation, redaction, gap handling | Unsupported claims are rejected |
| 5 — Bounded investigator | One stateful investigator with typed read-only tools | Tool budgets and prompt-injection tests pass |
| 6 — Paired validation | Isolated lab fixture, attack and benign workflow contracts | Ineffective proposals are rejected with counterexamples |
| 7 — Human approval | Exact proposal/validation digest and freshness checks | Replay, drift, and cross-environment attempts fail closed |
| 8 — UI and reporting | Timeline, claims, graph, proposal comparison, approval view | Analysts can inspect every material claim |
| 9 — Evaluation and hardening | Procedural benchmark, baselines, security tests, reproducible demo | Results and limitations are documented honestly |

## Current slice

The current implementation is deterministic. It includes the offline fixture
pipeline and a live, read-only RBAC metadata snapshot adapter that uses an
explicit kubeconfig context. The fixture represents a sanitized owned lab and
includes an alternate grant path so the report can demonstrate why deleting only
one binding is ineffective.

The local artifact store, replay API, live RBAC snapshot adapter, resource
history replay, and local case store cover the
non-database portion of the core-infrastructure and Kubernetes-adapter phases.
PostgreSQL, authentication, live audit sink connectivity, and durable jobs
remain unimplemented.

The deterministic shadow validator now covers the first non-cluster portion of
the paired-validation phase: it tests the attack regression, benign workflow
contracts, target preconditions, and evidence completeness.

The local approval gateway now covers the contract portion of the approval phase:
it binds one passed validation and proposal digest to an environment, expiry,
approver field, and single-use nonce. It is not an identity provider or executor.

The validation boundary is fail-closed on environment mismatch, snapshot drift,
finding/proposal action mismatch, contradictory behavior results, coverage
warnings, and counterexamples.

## Next slice

Add an authenticated audit-sink adapter, live resource-watch collection, and a
PostgreSQL repository implementation behind the case-store interface. Then use
the differential checker as a gate before introducing proposals backed by live
