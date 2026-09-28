# REPRISE threat model

## Assets

- integrity and provenance of audit evidence;
- correctness of supported authorization-path analysis;
- confidentiality of identity and resource metadata;
- approval integrity and environment binding;
- synthetic lab availability and reproducibility.

## Threats and controls

| Threat | Control | Residual limitation |
|---|---|---|
| Prompt injection in labels or user agents | Typed data/control separation and no arbitrary tools | Investigation quality can still degrade |
| Evidence poisoning | Preserve original bytes, hashes, source, and gaps | A compromised control plane can forge telemetry |
| Unsupported RBAC semantics | Coverage warnings and fail-closed execution boundary | The analyzer cannot prove behavior it does not model |
| Stale proposal | Future exact state fingerprints and expiry | Kubernetes changes are not globally atomic |
| Approval replay | Future single-use nonce and digest binding | Does not solve a compromised approver |
| Secret disclosure | Metadata-only default profile and synthetic fixtures | Names and metadata can still be sensitive |
| Denial of service | Bounded input, pages, time windows, and budgets | Delays remain possible under resource exhaustion |

## Out of scope for the first slice

Live credentials, public targets, real Secret values, production mutation,
multi-tenant deployment, and claims of complete cluster security.
