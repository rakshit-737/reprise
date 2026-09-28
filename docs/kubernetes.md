# Kubernetes adapter

## Purpose

`reprise.kubernetes_adapter.KubernetesRBACSnapshotter` captures a bounded,
metadata-only snapshot from one explicitly named kubeconfig context. It is the
first live-cluster integration and is read-only by construction.

## Collected resources

- namespaced `Role` objects;
- `ClusterRole` objects;
- namespaced `RoleBinding` objects;
- `ClusterRoleBinding` objects;
- `ServiceAccount` metadata: namespace, name, UID, and resource version.

The adapter does **not** request `Secret` objects, Secret contents, token
references, labels, annotations, audit events, arbitrary URLs, or arbitrary
resources. Labels and annotations are excluded because they are untrusted input
and can contain prompt-injection text.

## Run

```powershell
uv sync --extra kubernetes
uv run --extra kubernetes reprise-snapshot `
  --context kind-reprise-demo `
  --environment-id owned-kind-reprise-demo `
  --out artifacts/live-rbac `
  --artifact-root artifacts/store
```

The context is mandatory to avoid silently reading whichever context happens to
be current. The adapter uses bounded pagination and refuses snapshots exceeding
the configured item limit.

## Interpretation

The output is a reusable fixture and an evidence package with zero findings when
no audit events are supplied. It proves only that the listed metadata was
collected from the selected API server at capture time. It does not prove an
incident, historical authorization, complete authorizer-chain coverage, or
cluster security.

Kubernetes RBAC rules containing `nonResourceURLs` are excluded from the
resource-action model and recorded as explicit coverage gaps. Aggregated roles,
webhook/custom authorizers, and indirect identity-takeover paths remain outside
the supported model.
