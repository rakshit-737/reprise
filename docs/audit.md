# Kubernetes audit adapter

`reprise.audit_adapter` accepts a bounded JSON Lines export of Metadata-level
Kubernetes `AuditEvent` objects. It normalizes only:

- audit ID, stage, and timestamp;
- verb and service-account username;
- API group, resource, namespace, and object name;
- response status code.

Request bodies, response bodies, Secret data, token-like fields, duplicate JSON
keys, duplicate audit ID/stage pairs, malformed timestamps, and oversized input
are rejected. Unrecognized fields are not copied into the normalized artifact.

## Replay command

```powershell
uv run reprise-audit `
  --rbac-fixture examples/fixtures/alternate-path.json `
  --audit-log examples/fixtures/metadata-audit.jsonl `
  --out artifacts/audit-replay `
  --artifact-root artifacts/store
```

The command attaches normalized events to the supplied RBAC fixture and runs the
deterministic detector. It does not assert that an audit export is complete or
that an observed service account identifies a human operator.

The current adapter is replay-oriented. It does not tail files, read the
Kubernetes control-plane filesystem, or configure audit policy. A later live
collector must use an authenticated, bounded sink and record continuity gaps.
