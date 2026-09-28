"""Read-only Kubernetes RBAC snapshot adapter.

The adapter deliberately collects only metadata needed for the supported RBAC
model. It never requests Secret objects, Secret data, token material, labels,
annotations, or arbitrary resources, and it exposes no mutation operation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .fixture import FixtureError, canonical_json, load_fixture_bytes
from .models import Fixture

DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_ITEMS = 5_000
RBAC_API_GROUP = "rbac.authorization.k8s.io"


class KubernetesAdapterError(RuntimeError):
    """Raised when a read-only snapshot cannot be collected safely."""


@dataclass(frozen=True)
class SnapshotSummary:
    context: str
    environment_id: str
    server_fingerprint: str
    counts: dict[str, int]
    snapshot_artifact_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "environment_id": self.environment_id,
            "server_fingerprint": self.server_fingerprint,
            "counts": dict(self.counts),
            "snapshot_artifact_id": self.snapshot_artifact_id,
        }


def _load_kubernetes() -> tuple[Any, Any]:
    try:
        from kubernetes import client, config
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise KubernetesAdapterError("Kubernetes support is not installed; run `uv sync --extra kubernetes`") from exc
    return client, config


def _metadata(obj: Any, kind: str) -> Any:
    metadata = getattr(obj, "metadata", None)
    if metadata is None:
        raise KubernetesAdapterError(f"{kind} object has no metadata")
    return metadata


def _required_attr(obj: Any, name: str, field: str) -> str:
    value = getattr(obj, name, None)
    if not isinstance(value, str) or not value.strip():
        raise KubernetesAdapterError(f"Kubernetes object field {field} is missing")
    return value


def _optional_attr(obj: Any, name: str) -> str | None:
    value = getattr(obj, name, None)
    if value is None:
        return None
    if not isinstance(value, str):
        raise KubernetesAdapterError(f"Kubernetes object field {name} is not a string")
    return value


def _metadata_record(obj: Any, kind: str) -> dict[str, str | None]:
    metadata = _metadata(obj, kind)
    return {
        "name": _required_attr(metadata, "name", f"{kind}.metadata.name"),
        "namespace": _optional_attr(metadata, "namespace"),
        "uid": _required_attr(metadata, "uid", f"{kind}.metadata.uid"),
        "resource_version": _optional_attr(metadata, "resource_version"),
    }


def _role_to_record_with_warnings(obj: Any) -> tuple[dict[str, Any], list[str]]:
    """Convert a V1Role/V1ClusterRole-like object and report skipped semantics."""

    kind = "ClusterRole" if obj.__class__.__name__ == "V1ClusterRole" else "Role"
    metadata = _metadata_record(obj, kind)
    if kind == "Role" and metadata["namespace"] is None:
        raise KubernetesAdapterError("Role.metadata.namespace is missing")
    if kind == "ClusterRole":
        metadata["namespace"] = None
    raw_rules = getattr(obj, "rules", None) or []
    rules: list[dict[str, Any]] = []
    warnings: list[str] = []
    for index, raw_rule in enumerate(raw_rules):
        api_groups = list(getattr(raw_rule, "api_groups", None) or [""])
        resources = list(getattr(raw_rule, "resources", None) or [])
        verbs = list(getattr(raw_rule, "verbs", None) or [])
        if not resources or not verbs:
            non_resource_urls = list(getattr(raw_rule, "non_resource_urls", None) or [])
            if non_resource_urls:
                warnings.append(f"{kind}/{metadata['name']} rule {index} contains nonResourceURLs and was excluded")
                continue
            raise KubernetesAdapterError(f"{kind}/{metadata['name']} rule {index} lacks resources or verbs")
        rules.append(
            {
                "api_groups": api_groups,
                "resources": resources,
                "verbs": verbs,
                "resource_names": list(getattr(raw_rule, "resource_names", None) or []),
            }
        )
    return (
        {
            "kind": kind,
            "name": metadata["name"],
            "namespace": metadata["namespace"],
            "uid": metadata["uid"],
            "resource_version": metadata["resource_version"],
            "rules": rules,
            "aggregated": bool(getattr(obj, "aggregation_rule", None)),
        },
        warnings,
    )


def role_to_record(obj: Any) -> dict[str, Any]:
    """Convert a V1Role/V1ClusterRole-like object without copying metadata noise."""

    record, _warnings = _role_to_record_with_warnings(obj)
    return record


def role_binding_to_record(obj: Any) -> dict[str, Any]:
    """Convert a V1RoleBinding/V1ClusterRoleBinding-like object."""

    kind = "ClusterRoleBinding" if obj.__class__.__name__ == "V1ClusterRoleBinding" else "RoleBinding"
    metadata = _metadata_record(obj, kind)
    if kind == "RoleBinding" and metadata["namespace"] is None:
        raise KubernetesAdapterError("RoleBinding.metadata.namespace is missing")
    if kind == "ClusterRoleBinding":
        metadata["namespace"] = None
    raw_subjects = getattr(obj, "subjects", None) or []
    subjects: list[dict[str, str | None]] = []
    for index, subject in enumerate(raw_subjects):
        subjects.append(
            {
                "kind": _required_attr(subject, "kind", f"{kind}.subjects[{index}].kind"),
                "name": _required_attr(subject, "name", f"{kind}.subjects[{index}].name"),
                "namespace": _optional_attr(subject, "namespace"),
            }
        )
    role_ref = getattr(obj, "role_ref", None)
    if role_ref is None:
        raise KubernetesAdapterError(f"{kind}/{metadata['name']} has no roleRef")
    return {
        "kind": kind,
        "name": metadata["name"],
        "namespace": metadata["namespace"],
        "uid": metadata["uid"],
        "resource_version": metadata["resource_version"],
        "subjects": subjects,
        "role_ref": {
            "kind": _required_attr(role_ref, "kind", f"{kind}.roleRef.kind"),
            "name": _required_attr(role_ref, "name", f"{kind}.roleRef.name"),
            "api_group": _required_attr(role_ref, "api_group", f"{kind}.roleRef.apiGroup"),
        },
    }


def service_account_to_record(obj: Any) -> dict[str, str | None]:
    metadata = _metadata_record(obj, "ServiceAccount")
    if metadata["namespace"] is None:
        raise KubernetesAdapterError("ServiceAccount.metadata.namespace is missing")
    return {
        "name": metadata["name"],
        "namespace": metadata["namespace"],
        "uid": metadata["uid"],
        "resource_version": metadata["resource_version"],
    }


def fixture_payload(
    *,
    environment: dict[str, Any],
    roles: list[dict[str, Any]],
    role_bindings: list[dict[str, Any]],
    service_accounts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the intentionally narrow JSON payload consumed by the fixture parser."""

    return {
        "schema_version": "0.1",
        "environment": environment,
        "audit_events": [],
        "roles": roles,
        "role_bindings": role_bindings,
        "service_accounts": service_accounts,
        "workflow_contracts": [],
    }


def _continue_token(response: Any) -> str | None:
    metadata = getattr(response, "metadata", None)
    if metadata is None:
        return None
    for name in ("_continue", "continue_", "continue"):
        token = getattr(metadata, name, None)
        if isinstance(token, str) and token:
            return token
    return None


def _list_all(
    list_method: Callable[..., Any],
    *,
    resource_kind: str,
    page_size: int,
    max_items: int,
) -> list[Any]:
    items: list[Any] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"limit": page_size}
        if token is not None:
            kwargs["_continue"] = token
        response = list_method(**kwargs)
        page_items = list(getattr(response, "items", None) or [])
        items.extend(page_items)
        if len(items) > max_items:
            raise KubernetesAdapterError(f"{resource_kind} count exceeds the safety limit of {max_items}")
        next_token = _continue_token(response)
        if next_token is None:
            return items
        if next_token == token:
            raise KubernetesAdapterError(f"{resource_kind} pagination token did not advance")
        token = next_token


class KubernetesRBACSnapshotter:
    """Collect a bounded metadata-only RBAC snapshot from one kubeconfig context."""

    def __init__(
        self,
        *,
        context: str,
        environment_id: str,
        kubeconfig: str | Path | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_items: int = DEFAULT_MAX_ITEMS,
    ):
        if not context.strip():
            raise ValueError("context must be non-empty")
        if not environment_id.strip():
            raise ValueError("environment_id must be non-empty")
        if page_size < 1 or page_size > max_items:
            raise ValueError("page_size must be between 1 and max_items")
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.context = context
        self.environment_id = environment_id
        self.kubeconfig = str(kubeconfig) if kubeconfig is not None else None
        self.page_size = page_size
        self.max_items = max_items

    def capture(self) -> tuple[Fixture, SnapshotSummary]:
        client, config = _load_kubernetes()
        try:
            config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            api_client = client.ApiClient()
            try:
                server = getattr(getattr(api_client, "configuration", None), "host", None)
                if not isinstance(server, str) or not server:
                    raise KubernetesAdapterError("Kubernetes client did not expose an API server host")
                server_fingerprint = hashlib.sha256(server.encode("utf-8")).hexdigest()
                rbac_api = client.RbacAuthorizationV1Api(api_client)
                core_api = client.CoreV1Api(api_client)
                roles_raw = _list_all(
                    rbac_api.list_role_for_all_namespaces,
                    resource_kind="Role",
                    page_size=self.page_size,
                    max_items=self.max_items,
                )
                cluster_roles_raw = _list_all(
                    rbac_api.list_cluster_role,
                    resource_kind="ClusterRole",
                    page_size=self.page_size,
                    max_items=self.max_items,
                )
                bindings_raw = _list_all(
                    rbac_api.list_role_binding_for_all_namespaces,
                    resource_kind="RoleBinding",
                    page_size=self.page_size,
                    max_items=self.max_items,
                )
                cluster_bindings_raw = _list_all(
                    rbac_api.list_cluster_role_binding,
                    resource_kind="ClusterRoleBinding",
                    page_size=self.page_size,
                    max_items=self.max_items,
                )
                service_accounts_raw = _list_all(
                    core_api.list_service_account_for_all_namespaces,
                    resource_kind="ServiceAccount",
                    page_size=self.page_size,
                    max_items=self.max_items,
                )
                observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                role_records: list[dict[str, Any]] = []
                coverage_warnings: list[str] = []
                for role in roles_raw + cluster_roles_raw:
                    record, warnings = _role_to_record_with_warnings(role)
                    role_records.append(record)
                    coverage_warnings.extend(warnings)
                environment = {
                    "id": self.environment_id,
                    "mode": "live-read-only",
                    "kube_context": self.context,
                    "api_server_fingerprint": server_fingerprint,
                    "authorizers": ["RBAC objects observed; complete authorizer chain not verified"],
                    "snapshot_observed_at": observed_at,
                    "snapshot_complete": True,
                    "gaps": [
                        "Audit events are not collected by this adapter.",
                        "Labels and annotations are intentionally excluded as untrusted context.",
                        "The API server's complete authorizer chain was not queried.",
                        *coverage_warnings,
                    ],
                }
                payload = fixture_payload(
                    environment=environment,
                    roles=role_records,
                    role_bindings=[role_binding_to_record(item) for item in bindings_raw + cluster_bindings_raw],
                    service_accounts=[service_account_to_record(item) for item in service_accounts_raw],
                )
                source_bytes = canonical_json(payload)
                fixture = load_fixture_bytes(source_bytes)
                summary = SnapshotSummary(
                    context=self.context,
                    environment_id=self.environment_id,
                    server_fingerprint=server_fingerprint,
                    counts={
                        "roles": len(roles_raw),
                        "cluster_roles": len(cluster_roles_raw),
                        "role_bindings": len(bindings_raw),
                        "cluster_role_bindings": len(cluster_bindings_raw),
                        "service_accounts": len(service_accounts_raw),
                    },
                    snapshot_artifact_id=fixture.snapshot_artifact_id,
                )
                return fixture, summary
            finally:
                close = getattr(api_client, "close", None)
                if callable(close):
                    close()
        except (KubernetesAdapterError, FixtureError):
            raise
        except Exception as exc:
            raise KubernetesAdapterError(f"read-only Kubernetes snapshot failed: {exc}") from exc


def write_fixture(fixture: Fixture, path: str | Path) -> Path:
    """Write the canonical accepted source payload for replay."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(fixture.source_bytes)
    return destination
