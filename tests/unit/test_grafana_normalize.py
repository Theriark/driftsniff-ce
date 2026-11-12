"""The shaping the Grafana collector does before the pipeline sees the objects."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.grafana.normalize import (
    POLICIES_KEY,
    dashboard_object,
    folder_permissions,
    prepare_objects,
)


def test_lists_are_sorted_by_key() -> None:
    raw: Any = [{"uid": "b"}, {"uid": "a"}]
    assert [item["uid"] for item in prepare_objects("grafana-folders", "uid", raw)] == ["a", "b"]


def test_the_policy_tree_gets_a_fixed_key() -> None:
    (item,) = prepare_objects("grafana-notification-policies", "id", {"receiver": "ops"})
    assert item == {"receiver": "ops", "id": POLICIES_KEY}


@pytest.mark.parametrize("raw", [{}, [{"uid": ""}], [{"id": True}], ["text"]])
def test_a_list_without_usable_keys_is_a_bad_payload(raw: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects("grafana-teams", "id", raw)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_a_dashboard_keeps_its_model_and_the_folder_of_its_meta() -> None:
    answer: Any = {
        "dashboard": {"uid": "d1", "title": "Hosts", "version": 3},
        "meta": {"folderUid": "f1", "canSave": True, "version": 3},
    }
    assert dashboard_object(answer) == {
        "uid": "d1",
        "title": "Hosts",
        "folderUid": "f1",
        "dashboard": {"uid": "d1", "title": "Hosts", "version": 3},
    }


@pytest.mark.parametrize("answer", [[], {"dashboard": []}, {"dashboard": {"uid": 7}}])
def test_a_dashboard_answer_of_the_wrong_shape_is_a_bad_payload(answer: Any) -> None:
    with pytest.raises(CollectorError):
        dashboard_object(answer)


def test_permission_entries_are_keyed_by_subject_and_trimmed() -> None:
    entries: Any = [
        {"id": 9, "userId": 0, "teamId": 2, "team": "net", "role": "", "permission": 1},
        {"id": 8, "userId": 5, "userLogin": "erin", "teamId": 0, "permission": 2, "created": "x"},
        {"id": 7, "userId": 0, "teamId": 0, "role": "Editor", "permission": 2},
    ]
    folder = folder_permissions({"uid": "f1", "title": "Ops", "url": "/f"}, entries)
    assert folder == {
        "uid": "f1",
        "title": "Ops",
        "permissions": [
            {"subject": "role:Editor", "role": "Editor", "permission": 2},
            {"subject": "team:2", "team": "net", "role": "", "permission": 1},
            {"subject": "user:5", "userLogin": "erin", "permission": 2},
        ],
    }


@pytest.mark.parametrize("entries", [{}, [{"permission": 1}], [{"userId": 0, "role": ""}]])
def test_permission_answers_that_name_nobody_are_a_bad_payload(entries: Any) -> None:
    with pytest.raises(CollectorError):
        folder_permissions({"uid": "f1"}, entries)
