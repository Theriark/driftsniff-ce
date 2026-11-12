"""The reshaping the Proxmox VE collector does before the pipeline sees the objects."""

from typing import Any

import pytest

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.collectors.proxmox import normalize as shape


def test_numbered_keys_fold_into_one_list_per_kind_in_slot_order() -> None:
    config: Any = {"net10": "b", "net2": "a", "numa": 1, "numa0": "cpus=0-1", "efidisk0": "e"}
    folded = shape.fold_slots(config, ("net", "numa"))
    assert folded == {
        "numa": 1,
        "efidisk0": "e",
        "net[n]": [{"slot": "net2", "value": "a"}, {"slot": "net10", "value": "b"}],
        "numa[n]": [{"slot": "numa0", "value": "cpus=0-1"}],
    }


def test_member_lists_become_sorted_sets() -> None:
    assert shape.split_names("VM.Audit,Sys.Audit, VM.Audit") == ["Sys.Audit", "VM.Audit"]
    assert shape.split_names("") == []
    assert shape.split_names(None) is None


def test_acl_entries_are_keyed_and_administrator_entries_split_off() -> None:
    raw: Any = [
        {"path": "/", "type": "user", "ugid": "root@pam", "roleid": "Administrator"},
        {"path": "/vms", "type": "group", "ugid": "ops", "roleid": "PVEVMUser"},
    ]
    others, admins = shape.acl_entries(raw)
    assert [entry["id"] for entry in others] == ["/vms|group|ops|PVEVMUser"]
    assert [entry["id"] for entry in admins] == ["/|user|root@pam|Administrator"]


def test_tokens_are_lifted_out_of_their_users() -> None:
    raw: Any = [
        {"userid": "b@pve", "tokens": [{"tokenid": "t1", "privsep": 1}]},
        {"userid": "a@pve"},
    ]
    assert shape.tokens(raw) == [
        {"tokenid": "t1", "privsep": 1, "id": "b@pve!t1", "userid": "b@pve"}
    ]
    assert shape.users(raw)[1] == {"userid": "b@pve"}


def test_pool_members_keep_only_their_ids() -> None:
    pool: Any = {"poolid": "p", "members": [{"id": "qemu/2", "mem": 5}, {"id": "lxc/1"}]}
    assert shape.pool_members(pool)["members"] == ["lxc/1", "qemu/2"]


def test_options_get_the_fixed_key() -> None:
    assert shape.single({"enable": 1}) == [{"enable": 1, "id": "cluster"}]


@pytest.mark.parametrize("name", ["../x", "a/b", "", ".hidden", "a b", 7])
def test_a_name_that_could_change_a_path_is_refused(name: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        shape.path_segment(name)
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


@pytest.mark.parametrize(
    "raw",
    [{"vmid": 1}, [{"vmid": True}], [{"vmid": ""}], ["text"], [{"vmid": 1}, {"vmid": 1}]],
)
def test_an_answer_of_the_wrong_shape_fails_the_resource(raw: Any) -> None:
    with pytest.raises(CollectorError) as caught:
        shape.keyed(shape.object_list(raw), "vmid")
    assert caught.value.error_class == ERROR_BAD_PAYLOAD


def test_the_envelope_must_carry_data() -> None:
    assert shape.unwrap({"data": [1]}) == [1]
    with pytest.raises(CollectorError):
        shape.unwrap({"errors": {}})
