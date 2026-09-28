# Deterministic shadow validation

`reprise.validator` tests a candidate proposal against a virtual copy of the
accepted RBAC fixture. It never contacts Kubernetes and never mutates a target.

For each candidate it checks:

1. the suspicious action was allowed before the virtual deletion;
2. the suspicious action is blocked after the deletion;
3. every declared benign workflow was allowed before and remains allowed after;
4. each mutation target still matches its UID, namespace, name, and resource
   version precondition;
5. all material claims have evidence references;
6. the after-state has no supported-path coverage warnings.

Run the flagship candidates:

```powershell
uv run reprise-validate `
  --fixture examples/fixtures/alternate-path.json `
  --candidate naive_first_path_only `
  --out artifacts/validation
```

The naive candidate exits `3` and records the surviving alternate path:

```powershell
uv run reprise-validate `
  --fixture examples/fixtures/alternate-path.json `
  --candidate all_supported_paths `
  --out artifacts/validation
```

The corrected candidate exits `0` when the attack is blocked and the ConfigMap
workflow remains allowed.

This is a deterministic shadow test, not a Kubernetes API test. It does not
prove that undisclosed application behavior is preserved or that production and
the fixture have identical admission, authorizer, or workload behavior.
