# Architecture overview

The first release separates evidence collection, deterministic authorization
analysis, model-assisted investigation, validation, approval, and execution.

```text
fixture or audit adapter
        ↓
bounded evidence/artifact store
        ↓
detector → case coordinator → read-only investigator
                          ↓
              deterministic RBAC/evidence validators
                          ↓
              proposal → isolated validation → human approval
                          ↓
                    owned-lab executor only
```

The current code implements only the left side through deterministic report
generation. The investigator cannot execute arbitrary Kubernetes requests; the
future broker will expose typed, bounded observations instead.

The current second slice adds two concrete boundaries:

- `reprise.contracts` validates claims, proposal targets, proposal digests, and
  evidence-package references with strict Pydantic models;
- `reprise.api` exposes only local fixture replay and health/capability reads.
- `reprise.artifacts` stores accepted source bytes and normalized snapshots by
  SHA-256 using atomic writes and integrity checks.

The API is intentionally not authenticated yet and is documented as local-only.
The CLI is the first caller that persists artifacts; the API remains stateless by
default so a future authenticated service can choose its retention policy.

## Evidence boundary

Every material observation has a stable artifact reference derived from the
canonical accepted bytes. Reports cite those references and state limitations.
The evidence package is a reproducible output, not a chat transcript.

## State and trust boundaries

- monitored data is untrusted input;
- evidence normalization is bounded and schema-checked;
- RBAC analysis is pure deterministic computation;
- model output, when added, is untrusted until schema and evidence validation;
- approval is separate from execution credentials;
- lab execution is opt-in and never implied by investigation success.
