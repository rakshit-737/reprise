# Supported RBAC semantics (first slice)

This document is a scope boundary, not a claim that Kubernetes RBAC is fully
modeled.

## Supported

- `ServiceAccount` subjects with exact namespace/name matching;
- namespaced `Role` rules used through namespaced `RoleBinding` objects;
- a namespaced `RoleBinding` referring to a `ClusterRole`, evaluated in the
  binding namespace;
- `ClusterRoleBinding` referring to a `ClusterRole` for cluster-wide access;
- explicit API group, resource, verb, namespace, and named-object matching;
- supported `*` wildcards for verbs, API groups, and resources;
- `resourceNames` matching for named-object questions;
- deterministic enumeration of every matching binding/rule path present in the
  supplied snapshot.

The live snapshot adapter also records ServiceAccount metadata, but ServiceAccount
metadata alone is not an authorization grant and is not treated as a path.

## Explicitly unsupported or incomplete

- aggregated `ClusterRole` expansion;
- node, webhook, or custom authorizers;
- impersonation, `bind`, and `escalate` exploitability beyond warning metadata;
- workload creation, token theft, admission behavior, or indirect takeover paths;
- external identity mapping beyond exact service-account subjects;
- historical authorization state when the relevant resource version is absent;
- claims about access outside the supplied snapshot.
- `nonResourceURLs` rules; live captures exclude them and record a coverage gap.

If an unsupported feature is present, the analyzer emits a coverage warning. A
warning prevents the result from being described as complete; it does not turn a
supported matching path into an unknown path.

## Matching rule

For a principal `s`, action `a`, and object `o`, a path is present when a binding
matches the principal and its role reference resolves to a rule matching the
action/object tuple. Authorization is additive:

```text
allowed(s, a, o) = any(path grants a)
```

Removing one binding is therefore insufficient whenever another independent
path remains.
