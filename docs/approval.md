# Exact-digest approval gateway

`reprise.approval.ApprovalGateway` records a short-lived, single-use approval
capability bound to:

- one environment ID;
- one proposal SHA-256 digest;
- one passed shadow-validation digest;
- one approver identity supplied by the local caller;
- one random nonce;
- one expiry time.

The gateway rejects failed validation, cross-environment use, digest changes,
wrong nonces, expired approvals, and replay after consumption.

Because a `passed` validation contract itself requires snapshot agreement,
target-state agreement, evidence completeness, behavior agreement, and no
counterexamples, approval creation fails closed when any of those invariants are
tampered with.

## Local demonstration

Create an approval from a passed validation artifact:

```powershell
uv run reprise-approve --db artifacts/approvals.db create `
  --validation artifacts/validation/all_supported_paths.json `
  --approver operator `
  --out artifacts/approval.json
```

Consume it only when all exact values match:

```powershell
$approval = Get-Content artifacts/approval.json | ConvertFrom-Json
uv run reprise-approve --db artifacts/approvals.db consume `
  --approval artifacts/approval.json `
  --nonce $approval.nonce `
  --environment-id $approval.environment_id `
  --proposal-digest $approval.proposal_digest `
  --validation-digest $approval.validation_digest
```

This is not human authentication. The local `--approver` value is caller input,
the nonce is a capability, and no executor or Kubernetes mutation is connected.
A production implementation needs authenticated identity, role separation,
durable server-side storage, audit retention, and a separate execution boundary.
