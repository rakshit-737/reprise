# RBAC resource history replay

`reprise.resource_history` replays bounded JSONL watch events for `Role`,
`ClusterRole`, `RoleBinding`, `ClusterRoleBinding`, and `ServiceAccount`.

It preserves:

- event type and object identity;
- Kubernetes resource version;
- normalized RBAC specification digest;
- optional observation timestamp;
- bookmark watermarks;
- explicit continuity gaps.

An `ERROR` event with code `410` is reported as a resource-version-expired gap;
callers must relist before treating the history as complete. The parser never
stores labels, annotations, Secret data, token material, or arbitrary object
fields.

Replay an example:

```powershell
uv run reprise-history examples/fixtures/rbac-watch.jsonl `
  --out artifacts/history/replay.json
```

Exit code `3` indicates that the replay contains a continuity gap. A gap is not
silently converted into a complete snapshot.
