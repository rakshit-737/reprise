"""Read-only Kubernetes SubjectAccessReview differential checker."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Action, Fixture
from .rbac import PathAnalysis, enumerate_paths


class SubjectAccessReviewError(RuntimeError):
    """Raised when a read-only SubjectAccessReview cannot be completed."""


@dataclass(frozen=True)
class SubjectAccessReviewResult:
    context: str
    server_fingerprint: str
    principal: str
    action: Action
    allowed: bool
    denied: bool
    reason: str | None
    evaluation_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "server_fingerprint": self.server_fingerprint,
            "principal": self.principal,
            "action": self.action.to_dict(),
            "allowed": self.allowed,
            "denied": self.denied,
            "reason": self.reason,
            "evaluation_error": self.evaluation_error,
        }


@dataclass(frozen=True)
class DifferentialCheck:
    model_allowed: bool
    api_allowed: bool
    match: bool
    model_paths: tuple[dict[str, Any], ...]
    model_coverage_warnings: tuple[str, ...]
    sar: SubjectAccessReviewResult
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_allowed": self.model_allowed,
            "api_allowed": self.api_allowed,
            "match": self.match,
            "model_paths": list(self.model_paths),
            "model_coverage_warnings": list(self.model_coverage_warnings),
            "subject_access_review": self.sar.to_dict(),
            "limitations": list(self.limitations),
        }


def _load_kubernetes() -> tuple[Any, Any]:
    try:
        from kubernetes import client, config
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise SubjectAccessReviewError("Kubernetes support is not installed; run `uv sync --extra kubernetes`") from exc
    return client, config


class KubernetesSubjectAccessReviewer:
    """Submit one bounded SAR against an explicit kubeconfig context."""

    def __init__(self, *, context: str, kubeconfig: str | Path | None = None):
        if not context.strip():
            raise ValueError("context must be non-empty")
        self.context = context
        self.kubeconfig = str(kubeconfig) if kubeconfig is not None else None

    def check(self, principal: str, action: Action) -> SubjectAccessReviewResult:
        if not principal.strip():
            raise ValueError("principal must be non-empty")
        if not action.verb.strip() or not action.resource.strip():
            raise ValueError("action verb and resource must be non-empty")
        client, config = _load_kubernetes()
        try:
            config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            api_client = client.ApiClient()
            try:
                server = getattr(getattr(api_client, "configuration", None), "host", None)
                if not isinstance(server, str) or not server:
                    raise SubjectAccessReviewError("Kubernetes client did not expose an API server host")
                review = client.V1SubjectAccessReview(
                    spec=client.V1SubjectAccessReviewSpec(
                        user=principal,
                        resource_attributes=client.V1ResourceAttributes(
                            group=action.api_group,
                            resource=action.resource,
                            namespace=action.namespace,
                            name=action.resource_name,
                            verb=action.verb,
                        ),
                    )
                )
                response = client.AuthorizationV1Api(api_client).create_subject_access_review(review)
                status = getattr(response, "status", None)
                allowed = bool(getattr(status, "allowed", False))
                denied = bool(getattr(status, "denied", False))
                return SubjectAccessReviewResult(
                    context=self.context,
                    server_fingerprint=hashlib.sha256(server.encode("utf-8")).hexdigest(),
                    principal=principal,
                    action=action,
                    allowed=allowed,
                    denied=denied,
                    reason=getattr(status, "reason", None),
                    evaluation_error=getattr(status, "evaluation_error", None),
                )
            finally:
                close = getattr(api_client, "close", None)
                if callable(close):
                    close()
        except SubjectAccessReviewError:
            raise
        except Exception as exc:
            raise SubjectAccessReviewError(f"SubjectAccessReview failed: {exc}") from exc


def differential_check(
    fixture: Fixture,
    reviewer: KubernetesSubjectAccessReviewer,
    principal: str,
    action: Action,
) -> DifferentialCheck:
    """Compare the supported local model with the API server's SAR result."""

    model: PathAnalysis = enumerate_paths(fixture, principal, action)
    sar = reviewer.check(principal, action)
    decision_defined = sar.allowed or sar.denied
    return DifferentialCheck(
        model_allowed=model.allowed,
        api_allowed=sar.allowed,
        match=(sar.evaluation_error is None and decision_defined and model.allowed == sar.allowed),
        model_paths=tuple(path.to_dict() for path in model.paths),
        model_coverage_warnings=model.coverage_warnings,
        sar=sar,
        limitations=(
            "SubjectAccessReview is evaluated against current API-server state, not historical event-time state.",
            "A matching result compares only the explicitly supported model; unsupported authorizers and semantics remain outside the proof boundary.",
        ),
    )
