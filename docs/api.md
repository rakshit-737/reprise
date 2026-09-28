# Local replay API

The current API is a deliberately unauthenticated, loopback-oriented replay
surface. It accepts a bounded sanitized fixture and returns the same validated
evidence package produced by the CLI.

Run it with:

```powershell
uv run uvicorn reprise.api:app --host 127.0.0.1 --port 8787
```

## Endpoints

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/health` | Reports version and explicit read-only replay mode |
| `GET` | `/v1/capabilities` | Reports supported input/output and confirms no mutation endpoints |
| `POST` | `/v1/replay` | Validates and analyzes one metadata-only JSON fixture |

## Replay request

- `Content-Type: application/json` is required.
- Body limit is 1,000,000 bytes.
- Secret values, token fields, request/response bodies, and similar sensitive
  fields are rejected.
- The request is not allowed to name a filesystem path or a Kubernetes endpoint.

## Safety status

This API has no authentication and no live Kubernetes credentials. Bind it to
`127.0.0.1` for local use. Do not expose it to a network or treat it as a
production service. Authentication, durable storage, and an authenticated
read-only API are later acceptance-gated phases.
