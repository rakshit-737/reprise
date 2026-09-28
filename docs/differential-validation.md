# Differential authorization validation

`reprise.sar.KubernetesSubjectAccessReviewer` submits one explicit,
read-only `SubjectAccessReview` to the selected Kubernetes API server. It never
creates, updates, deletes, or patches RBAC objects.

When an accepted RBAC fixture is supplied, `reprise-sar` compares the API
server's current decision with REPRISE's supported deterministic model:

```powershell
uv run --extra kubernetes reprise-sar `
  --context kind-reprise-demo `
  --principal system:serviceaccount:kube-system:bootstrap-signer `
  --verb get `
  --resource configmaps `
  --namespace kube-public `
  --rbac-fixture artifacts/live-rbac/rbac-fixture.json
```

Exit codes:

- `0`: SAR completed and matched the supported model;
- `2`: input, kubeconfig, or API error;
- `3`: SAR completed but disagreed with the supported model.

A match is not proof of historical authorization or complete cluster security.
The check uses current API-server state and remains limited by unsupported
authorizers, aggregation, and indirect privilege paths.
