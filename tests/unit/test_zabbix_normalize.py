"""The reshaping the Zabbix collector does before the pipeline sees the objects."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.zabbix.client import api_url
from driftsniff.collectors.zabbix.normalize import SECRET_VALUE_FIELD, prepare_objects
from driftsniff.collectors.zabbix.resources import (
    BEARER_FROM,
    HOST_GROUPS_FROM,
    RESOURCE_BY_NAME,
)


def test_a_secret_macro_value_is_moved_and_a_text_macro_value_stays() -> None:
    raw: Any = [
        {
            "hostid": "1",
            "macros": [
                {"macro": "{$A}", "value": "plain", "type": "0"},
                {"macro": "{$B}", "value": "CANARY-zabbix-norm-00", "type": "1"},
                {"macro": "{$C}", "value": "secret/path:key", "type": "2"},
            ],
        }
    ]
    (host,) = prepare_objects("zabbix-hosts", "hostid", raw)
    assert host["macros"] == [
        {"macro": "{$A}", "value": "plain", "type": "0"},
        {"macro": "{$B}", SECRET_VALUE_FIELD: "CANARY-zabbix-norm-00", "type": "1"},
        {"macro": "{$C}", "value": "secret/path:key", "type": "2"},
    ]


def test_a_secret_global_macro_value_is_moved() -> None:
    raw: Any = [{"globalmacroid": "3", "macro": "{$P}", "value": "x", "type": "1"}]
    (macro,) = prepare_objects("zabbix-global-macros", "globalmacroid", raw)
    assert "value" not in macro and macro[SECRET_VALUE_FIELD] == "x"


def test_older_names_get_the_newer_name() -> None:
    raw: Any = [{"hostid": "1", "groups": [{"groupid": "2", "name": "g"}]}]
    (host,) = prepare_objects("zabbix-hosts", "hostid", raw)
    assert host["hostgroups"] == [{"groupid": "2", "name": "g"}] and "groups" not in host
    raw = [{"usrgrpid": "7", "rights": [{"id": "2", "permission": "3"}]}]
    (group,) = prepare_objects("zabbix-user-groups", "usrgrpid", raw)
    assert group["hostgroup_rights"] == [{"id": "2", "permission": "3"}]


def test_objects_are_sorted_by_numeric_id() -> None:
    raw: Any = [{"groupid": "10"}, {"groupid": "9"}, {"groupid": "100"}]
    objects = prepare_objects("zabbix-host-groups", "groupid", raw)
    assert [item["groupid"] for item in objects] == ["9", "10", "100"]


def test_the_authentication_settings_get_one_key() -> None:
    (settings,) = prepare_objects("zabbix-authentication", "id", {"authentication_type": "0"})
    assert settings == {"authentication_type": "0", "id": "authentication"}


@pytest.mark.parametrize(
    ("name", "key", "raw"),
    [
        ("zabbix-hosts", "hostid", {}),
        ("zabbix-hosts", "hostid", [{"host": "no id"}]),
        ("zabbix-hosts", "hostid", [{"hostid": True}]),
        ("zabbix-hosts", "hostid", [{"hostid": ""}]),
        ("zabbix-authentication", "id", []),
    ],
)
def test_a_wrong_shape_is_a_bad_payload(name: str, key: str, raw: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        prepare_objects(name, key, raw)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_the_parameters_follow_the_version() -> None:
    hosts = RESOURCE_BY_NAME["zabbix-hosts"]
    old, new = hosts.params((6, 0)), hosts.params((7, 0))
    assert "selectGroups" in old and "selectHostGroups" not in old
    assert "proxy_hostid" in old["output"]  # type: ignore[operator]
    assert "selectHostGroups" in new and "proxyid" in new["output"]  # type: ignore[operator]
    groups = RESOURCE_BY_NAME["zabbix-user-groups"]
    assert "selectRights" in groups.params((6, 0))
    assert "selectHostGroupRights" in groups.params(HOST_GROUPS_FROM)
    assert BEARER_FROM == (6, 4)


def test_the_endpoint_is_below_the_frontend_address() -> None:
    assert api_url("https://z.example.invalid/zabbix") == (
        "https://z.example.invalid/zabbix/api_jsonrpc.php"
    )
    assert api_url("https://z.example.invalid/api_jsonrpc.php") == (
        "https://z.example.invalid/api_jsonrpc.php"
    )
