from types import SimpleNamespace

import pytest

from reprise.detect import detect_findings
from reprise.fixture import load_fixture
from reprise.models import Action
from reprise.sar import (
    KubernetesSubjectAccessReviewer,
    SubjectAccessReviewResult,
    differential_check,
)


def test_sar_uses_explicit_context_and_only_authorization_api(monkeypatch):
    calls = []

    class FakeConfig:
        @staticmethod
        def load_kube_config(**kwargs):
            calls.append(("config", kwargs))

    class FakeApiClient:
        def __init__(self):
            self.configuration = SimpleNamespace(host="https://127.0.0.1:6443")

        def close(self):
            calls.append(("close", {}))

    class FakeResourceAttributes:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FakeSpec:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FakeReview:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FakeAuthorization:
        def __init__(self, api_client):
            calls.append(("authorization-api", {"api_client": api_client}))

        def create_subject_access_review(self, review):
            calls.append(("sar", review))
            return SimpleNamespace(status=SimpleNamespace(allowed=True, denied=False, reason="RBAC", evaluation_error=None))

    class FakeClient:
        ApiClient = FakeApiClient
        V1ResourceAttributes = FakeResourceAttributes
        V1SubjectAccessReviewSpec = FakeSpec
        V1SubjectAccessReview = FakeReview
        AuthorizationV1Api = FakeAuthorization

    monkeypatch.setattr("reprise.sar._load_kubernetes", lambda: (FakeClient, FakeConfig))
    action = Action("get", "", "configmaps", "reprise-demo", "app-config")
    result = KubernetesSubjectAccessReviewer(context="kind-reprise-demo").check("system:serviceaccount:reprise-demo:preview-bot", action)

    assert result.allowed is True
    assert calls[0] == ("config", {"config_file": None, "context": "kind-reprise-demo"})
    review = next(payload for name, payload in calls if name == "sar")
    assert review.spec.user == "system:serviceaccount:reprise-demo:preview-bot"
    assert review.spec.resource_attributes.resource == "configmaps"
    assert review.spec.resource_attributes.name == "app-config"
    assert not any(name in {"delete", "patch", "replace", "create_role_binding"} for name, _ in calls)


def test_sar_rejects_empty_inputs():
    reviewer = KubernetesSubjectAccessReviewer(context="kind-reprise-demo")
    with pytest.raises(ValueError):
        reviewer.check("", Action("get", "", "pods", "default", None))
    with pytest.raises(ValueError):
        reviewer.check("system:serviceaccount:default:default", Action("", "", "pods", "default", None))


def test_differential_check_reports_match(fixture_file):
    fixture = load_fixture(fixture_file())

    class FakeReviewer:
        def check(self, principal, action):
            return SubjectAccessReviewResult(
                context="kind-reprise-demo",
                server_fingerprint="a" * 64,
                principal=principal,
                action=action,
                allowed=True,
                denied=False,
                reason="allowed",
                evaluation_error=None,
            )

    finding = detect_findings(fixture)[0]
    result = differential_check(fixture, FakeReviewer(), finding.principal, finding.action)
    assert result.match is True
    assert len(result.model_paths) == 2


def test_differential_check_does_not_call_undefined_sar_decision_a_match(fixture_file):
    fixture = load_fixture(fixture_file())

    class UnknownReviewer:
        def check(self, principal, action):
            return SubjectAccessReviewResult(
                context="kind-reprise-demo",
                server_fingerprint="a" * 64,
                principal=principal,
                action=action,
                allowed=False,
                denied=False,
                reason=None,
                evaluation_error="authorizer unavailable",
            )

    finding = detect_findings(fixture)[0]
    result = differential_check(fixture, UnknownReviewer(), finding.principal, finding.action)
    assert result.match is False
