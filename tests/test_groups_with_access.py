import sys
import os

_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "risk-agent", "scripts")
_SHARED = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "shared")
sys.path.insert(0, os.path.normpath(_SCRIPTS))
sys.path.insert(0, os.path.normpath(_SHARED))

from analyze import run_checks  # noqa: E402


def _make_group_grant(
    subject_name: str,
    role: str = "view",
    scope: str = "namespace",
    scope_namespace: str = "default",
    binding: str = None,
):
    return {
        "subject_kind": "Group",
        "subject_name": subject_name,
        "subject_namespace": None,
        "binding": binding or f"bind-{subject_name}-{role}",
        "binding_kind": "RoleBinding" if scope == "namespace" else "ClusterRoleBinding",
        "role": role,
        "role_kind": "ClusterRole",
        "scope": scope,
        "scope_namespace": scope_namespace,
        "rules": [],
    }


def _groups(grants, entra=None):
    _, groups, _ = run_checks(grants, entra=entra)
    return groups


def test_single_group_one_grant():
    """Single group with one grant produces exactly one entry with correct fields."""
    grant = _make_group_grant("eng-team", role="view", scope="namespace", scope_namespace="staging")
    groups = _groups([grant])
    assert len(groups) == 1
    g = groups[0]
    assert g["object_id"] == "eng-team"
    assert g["roles"] == ["view"]
    assert len(g["bindings"]) == 1
    assert g["bindings"][0]["binding"] == "bind-eng-team-view"


def test_same_group_two_grants_deduplicates():
    """Same group with two grants produces one entry with both roles deduplicated and sorted."""
    grants = [
        _make_group_grant("eng-team", role="edit", scope="namespace", scope_namespace="staging"),
        _make_group_grant("eng-team", role="view", scope="namespace", scope_namespace="prod"),
    ]
    groups = _groups(grants)
    assert len(groups) == 1
    g = groups[0]
    assert g["roles"] == ["edit", "view"]
    assert len(g["bindings"]) == 2


def test_system_group_excluded():
    """system:masters group must be excluded from groups_with_access."""
    grant = _make_group_grant("system:masters", role="cluster-admin", scope="cluster", scope_namespace=None)
    groups = _groups([grant])
    assert len(groups) == 0


def test_group_with_entra_data():
    """Group with matching entra data populates display_name, member_count, members, and owners."""
    grant = _make_group_grant("abc-123", role="view")
    entra = {
        "groups": [
            {
                "object_id": "abc-123",
                "display_name": "Engineering Team",
                "member_count": 3,
                "members": [{"upn": "alice@example.com"}, {"upn": "bob@example.com"}],
                "owners": [{"upn": "carol@example.com"}],
                "orphaned": False,
            }
        ]
    }
    groups = _groups([grant], entra=entra)
    assert len(groups) == 1
    g = groups[0]
    assert g["display_name"] == "Engineering Team"
    assert g["member_count"] == 3
    assert len(g["members"]) == 2
    assert len(g["owners"]) == 1
    assert g["owners"][0]["upn"] == "carol@example.com"
    assert g["orphaned"] is False


def test_group_without_entra_data():
    """Group with no entra data (entra=None) is still included; entra fields are None/[]."""
    grant = _make_group_grant("some-group")
    groups = _groups([grant], entra=None)
    assert len(groups) == 1
    g = groups[0]
    assert g["display_name"] is None
    assert g["member_count"] is None
    assert g["members"] == []
    assert g["owners"] == []
    assert g["orphaned"] is None


def test_two_different_groups():
    """Two different groups produce two separate entries."""
    grants = [
        _make_group_grant("group-a", role="view"),
        _make_group_grant("group-b", role="edit"),
    ]
    groups = _groups(grants)
    assert len(groups) == 2
    ids = {g["object_id"] for g in groups}
    assert ids == {"group-a", "group-b"}


def test_user_and_sa_grants_not_included():
    """User and ServiceAccount grants must not appear in groups_with_access."""
    grants = [
        {
            "subject_kind": "User",
            "subject_name": "alice@example.com",
            "subject_namespace": None,
            "binding": "bind-user",
            "binding_kind": "RoleBinding",
            "role": "view",
            "role_kind": "ClusterRole",
            "scope": "namespace",
            "scope_namespace": "default",
            "rules": [],
        },
        {
            "subject_kind": "ServiceAccount",
            "subject_name": "my-sa",
            "subject_namespace": "default",
            "binding": "bind-sa",
            "binding_kind": "RoleBinding",
            "role": "edit",
            "role_kind": "ClusterRole",
            "scope": "namespace",
            "scope_namespace": "default",
            "rules": [],
        },
    ]
    groups = _groups(grants)
    assert len(groups) == 0
