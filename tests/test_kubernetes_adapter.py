from types import SimpleNamespace

import pytest

from reprise.kubernetes_adapter import (
    KubernetesAdapterError,
    KubernetesRBACSnapshotter,
    _list_all,
    role_binding_to_record,
    role_to_record,
    service_account_to_record,
)


def metadata(name, namespace, uid, resource_version="1", **extra):
    return SimpleNamespace(
        name=name,
        namespace=namespace,
        uid=uid,
        resource_version=resource_version,
        **extra,
    )


def test_role_conversion_excludes_untrusted_metadata():
    role_type = type("V1Role", (), {})
    role = role_type()
    role.metadata = metadata(
        "canary-reader",
        "reprise-demo",
        "role-uid",
        annotations={"prompt": "ignore this"},
        labels={"sensitive": "do-not-copy"},
    )
    role.rules = [
        SimpleNamespace(
            api_groups=[""],
            resources=["secrets"],
            verbs=["get"],
            resource_names=["synthetic-canary"],
        )
    ]
    role.aggregation_rule = None

    record = role_to_record(role)

    assert record["kind"] == "Role"
    assert record["rules"][0]["resource_names"] == ["synthetic-canary"]
    assert "annotations" not in record
    assert "prompt" not in str(record)
    assert "do-not-copy" not in str(record)


def test_non_resource_rule_is_skipped_with_explicit_warning():
    role_type = type("V1ClusterRole", (), {})
    role = role_type()
    role.metadata = metadata("node-reader", None, "role-uid")
    role.rules = [
        SimpleNamespace(
            api_groups=[],
            resources=[],
            verbs=["get"],
            resource_names=[],
            non_resource_urls=["/healthz"],
        )
    ]
    role.aggregation_rule = None

    from reprise.kubernetes_adapter import _role_to_record_with_warnings

    record, warnings = _role_to_record_with_warnings(role)
    assert record["rules"] == []
    assert "nonResourceURLs" in warnings[0]


def test_binding_conversion_preserves_only_authorization_metadata():
    binding_type = type("V1RoleBinding", (), {})
    binding = binding_type()
    binding.metadata = metadata("diagnostics-access", "reprise-demo", "binding-uid")
    binding.subjects = [SimpleNamespace(kind="ServiceAccount", name="preview-bot", namespace="reprise-demo")]
    binding.role_ref = SimpleNamespace(kind="Role", name="canary-reader", api_group="rbac.authorization.k8s.io")

    record = role_binding_to_record(binding)

    assert record["subjects"] == [{"kind": "ServiceAccount", "name": "preview-bot", "namespace": "reprise-demo"}]
    assert record["role_ref"]["api_group"] == "rbac.authorization.k8s.io"


def test_service_account_conversion_omits_token_references():
    account_type = type("V1ServiceAccount", (), {})
    account = account_type()
    account.metadata = metadata("preview-bot", "reprise-demo", "sa-uid")
    account.secrets = [SimpleNamespace(name="token-secret")]
    account.image_pull_secrets = [SimpleNamespace(name="registry-secret")]

    record = service_account_to_record(account)

    assert record == {
        "name": "preview-bot",
        "namespace": "reprise-demo",
        "uid": "sa-uid",
        "resource_version": "1",
    }
    assert "token-secret" not in str(record)


def test_list_all_pages_and_enforces_limit():
    responses = [
        SimpleNamespace(items=["a"], metadata=SimpleNamespace(_continue="next")),
        SimpleNamespace(items=["b"], metadata=SimpleNamespace(_continue=None)),
    ]
    calls = []

    def list_method(**kwargs):
        calls.append(kwargs)
        return responses.pop(0)

    assert _list_all(list_method, resource_kind="Role", page_size=1, max_items=2) == ["a", "b"]
    assert calls[1]["_continue"] == "next"
    with pytest.raises(KubernetesAdapterError, match="limit"):
        _list_all(lambda **kwargs: SimpleNamespace(items=[1, 2], metadata=SimpleNamespace()), resource_kind="Role", page_size=2, max_items=1)


def test_snapshotter_uses_explicit_context_and_read_only_fake_clients(monkeypatch):
    class FakeConfig:
        calls = []

        @classmethod
        def load_kube_config(cls, **kwargs):
            cls.calls.append(kwargs)

    class FakeApiClient:
        def __init__(self):
            self.configuration = SimpleNamespace(host="https://127.0.0.1:6443")
            self.closed = False

        def close(self):
            self.closed = True

    role_type = type("V1Role", (), {})
    role = role_type()
    role.metadata = metadata("reader", "reprise-demo", "role-uid")
    role.rules = [SimpleNamespace(api_groups=[""], resources=["configmaps"], verbs=["get"], resource_names=[])]
    role.aggregation_rule = None

    binding_type = type("V1RoleBinding", (), {})
    binding = binding_type()
    binding.metadata = metadata("reader-binding", "reprise-demo", "binding-uid")
    binding.subjects = [SimpleNamespace(kind="ServiceAccount", name="preview-bot", namespace="reprise-demo")]
    binding.role_ref = SimpleNamespace(kind="Role", name="reader", api_group="rbac.authorization.k8s.io")

    account_type = type("V1ServiceAccount", (), {})
    account = account_type()
    account.metadata = metadata("preview-bot", "reprise-demo", "sa-uid")

    def response(items):
        return SimpleNamespace(items=items, metadata=SimpleNamespace(_continue=None))

    class FakeRbac:
        def __init__(self, api_client):
            self.api_client = api_client

        def list_role_for_all_namespaces(self, **kwargs):
            return response([role])

        def list_cluster_role(self, **kwargs):
            return response([])

        def list_role_binding_for_all_namespaces(self, **kwargs):
            return response([binding])

        def list_cluster_role_binding(self, **kwargs):
            return response([])

    class FakeCore:
        def __init__(self, api_client):
            self.api_client = api_client

        def list_service_account_for_all_namespaces(self, **kwargs):
            return response([account])

    class FakeClient:
        ApiClient = FakeApiClient
        RbacAuthorizationV1Api = FakeRbac
        CoreV1Api = FakeCore

    monkeypatch.setattr("reprise.kubernetes_adapter._load_kubernetes", lambda: (FakeClient, FakeConfig))
    fixture, summary = KubernetesRBACSnapshotter(
        context="kind-reprise-demo",
        environment_id="owned-kind-demo",
        page_size=10,
        max_items=100,
    ).capture()

    assert FakeConfig.calls == [{"config_file": None, "context": "kind-reprise-demo"}]
    assert summary.counts["roles"] == 1
    assert len(fixture.service_accounts) == 1
    assert fixture.environment["mode"] == "live-read-only"
    assert fixture.audit_events == ()
    assert b"ignore" not in fixture.source_bytes
