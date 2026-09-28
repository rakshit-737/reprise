"""Pure authorization analysis for the explicitly supported RBAC subset."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .models import Action, AuthorizationPath, Fixture, Role, RoleBinding, Rule

RBAC_API_GROUP = "rbac.authorization.k8s.io"


@dataclass(frozen=True)
class PathAnalysis:
    principal: str
    action: Action
    paths: tuple[AuthorizationPath, ...]
    coverage_warnings: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return bool(self.paths)

    def to_dict(self) -> dict[str, object]:
        return {
            "principal": self.principal,
            "action": self.action.to_dict(),
            "allowed": self.allowed,
            "paths": [path.to_dict() for path in self.paths],
            "coverage_warnings": list(self.coverage_warnings),
        }


def service_account_principal(namespace: str, name: str) -> str:
    return f"system:serviceaccount:{namespace}:{name}"


def _matches(patterns: Iterable[str], value: str) -> bool:
    return "*" in patterns or value in patterns


def rule_matches(rule: Rule, action: Action) -> bool:
    """Return whether one supported rule matches one named API action."""

    if not _matches(rule.api_groups, action.api_group):
        return False
    if not _matches(rule.resources, action.resource):
        return False
    if not _matches(rule.verbs, action.verb):
        return False
    if rule.resource_names:
        # resourceNames is an exact-name selector in this supported model; it is
        # not treated as a wildcard even when a fixture contains "*".
        return action.resource_name is not None and action.resource_name in rule.resource_names
    return True


def _subject_matches(binding: RoleBinding, principal: str) -> bool:
    for subject in binding.subjects:
        if subject.kind != "ServiceAccount" or subject.namespace is None:
            continue
        if service_account_principal(subject.namespace, subject.name) == principal:
            return True
    return False


def _role_index(fixture: Fixture) -> dict[tuple[str, str | None, str], Role]:
    return {(role.kind, role.namespace, role.name): role for role in fixture.roles}


def _resolve_role(binding: RoleBinding, roles: dict[tuple[str, str | None, str], Role]) -> Role | None:
    if binding.role_ref_kind == "Role":
        return roles.get(("Role", binding.namespace, binding.role_ref_name))
    if binding.role_ref_kind == "ClusterRole":
        return roles.get(("ClusterRole", None, binding.role_ref_name))
    return None


def enumerate_paths(
    fixture: Fixture,
    principal: str,
    action: Action,
    *,
    excluded_binding_uids: frozenset[str] = frozenset(),
) -> PathAnalysis:
    """Enumerate all matching grant paths under the supported model.

    ``excluded_binding_uids`` is used only for deterministic counterexample
    analysis; it does not mutate the fixture or imply that execution occurred.
    """

    roles = _role_index(fixture)
    paths: list[AuthorizationPath] = []
    warnings: list[str] = []

    for binding in fixture.role_bindings:
        if binding.uid in excluded_binding_uids:
            continue
        if binding.role_ref_api_group != RBAC_API_GROUP:
            warnings.append(f"binding {binding.kind}/{binding.name} uses unsupported roleRef api group {binding.role_ref_api_group!r}")
            continue
        if not _subject_matches(binding, principal):
            continue

        if binding.kind == "RoleBinding":
            if action.namespace != binding.namespace:
                continue
            if binding.role_ref_kind not in {"Role", "ClusterRole"}:
                warnings.append(f"binding RoleBinding/{binding.name} uses unsupported roleRef kind {binding.role_ref_kind!r}")
                continue
        elif binding.kind == "ClusterRoleBinding":
            if binding.role_ref_kind != "ClusterRole":
                warnings.append(f"binding ClusterRoleBinding/{binding.name} does not reference a ClusterRole")
                continue
        else:
            warnings.append(f"binding {binding.kind}/{binding.name} is outside the supported model")
            continue

        role = _resolve_role(binding, roles)
        if role is None:
            warnings.append(f"roleRef {binding.role_ref_kind}/{binding.role_ref_name} for {binding.kind}/{binding.name} was not present in the snapshot")
            continue
        if role.aggregated:
            warnings.append(f"aggregated ClusterRole/{role.name} is not expanded; paths through it are incomplete")
            continue
        if role.kind == "Role" and role.namespace != binding.namespace:
            warnings.append(f"Role/{role.name} resolved outside binding namespace for {binding.name}")
            continue

        for rule_index, rule in enumerate(role.rules):
            if rule_matches(rule, action):
                paths.append(
                    AuthorizationPath(
                        binding_kind=binding.kind,
                        binding_name=binding.name,
                        binding_namespace=binding.namespace,
                        binding_uid=binding.uid,
                        role_kind=role.kind,
                        role_name=role.name,
                        role_namespace=role.namespace,
                        role_uid=role.uid,
                        rule_index=rule_index,
                    )
                )

    # Stable output makes reports, hashes, and tests reproducible.
    paths.sort(
        key=lambda path: (
            path.binding_kind,
            path.binding_namespace or "",
            path.binding_name,
            path.role_kind,
            path.role_namespace or "",
            path.role_name,
            path.rule_index,
        )
    )
    return PathAnalysis(
        principal=principal,
        action=action,
        paths=tuple(paths),
        coverage_warnings=tuple(dict.fromkeys(warnings)),
    )
