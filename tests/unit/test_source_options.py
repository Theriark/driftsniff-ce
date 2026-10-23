"""The source options the forms of P10-T5 add: resources turned off and the XO credential expiry."""

from typing import Any

import pytest

from driftsniff.db.engine import Database
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources.service import SourceService, SourceValidationError

MASTER = MasterKey(bytes(range(32)))
CANARY = "CANARY-options-credential-0001"
ADDRESS = "https://203.0.113.10:8443"


@pytest.fixture
def service(store: Database) -> SourceService:
    return SourceService(store, CredentialCipher.from_master(MASTER))


def polled(source_type: str, **options: Any) -> dict[str, Any]:
    return {
        "name": f"lab-{source_type}",
        "source_type": source_type,
        "actor": "admin",
        "base_url": ADDRESS,
        "credential": CANARY,
        "options": options,
    }


def test_resources_off_and_the_expiry_date_are_stored(service: SourceService) -> None:
    view = service.create(
        **polled("xo", resources_off=["pifs", "pbds"], credential_expires_on="2026-11-30")
    )
    assert view.options["resources_off"] == ["pifs", "pbds"]
    assert view.options["credential_expires_on"] == "2026-11-30"
    unifi = service.create(**polled("unifi", resources_off=["unifi-devices"]))
    assert unifi.options == {"resources_off": ["unifi-devices"]}
    updated = service.update(unifi.id, actor="admin", options={})
    assert updated.options == {}


@pytest.mark.parametrize(
    "value",
    ["unifi-devices", ["a", "a"], [""], [1], ["x" * 101], ["tab\there"], ["n"] * 101],
    ids=["text", "twice", "blank", "number", "too long", "control", "too many"],
)
def test_resources_off_must_be_a_list_of_distinct_names(
    service: SourceService, value: object
) -> None:
    with pytest.raises(SourceValidationError, match="resources_off"):
        service.create(**polled("unifi", resources_off=value))


BAD_DATES = ["2026-13-01", "30/11/2026", "2026-1-5", "", "tomorrow", 20261130]


@pytest.mark.parametrize("value", BAD_DATES)
def test_the_expiry_date_is_written_as_year_month_day(
    service: SourceService, value: object
) -> None:
    with pytest.raises(SourceValidationError, match="credential_expires_on"):
        service.create(**polled("xo", credential_expires_on=value))


def test_the_options_belong_to_their_types(service: SourceService) -> None:
    with pytest.raises(SourceValidationError, match="only an xo source"):
        service.create(**polled("unifi", credential_expires_on="2026-11-30"))
    with pytest.raises(SourceValidationError, match="only a unifi or xo source"):
        service.create(
            name="pusher", source_type="push", actor="admin", options={"resources_off": ["x"]}
        )
    unifi = service.create(**polled("unifi"))
    with pytest.raises(SourceValidationError, match="only an xo source"):
        service.update(unifi.id, actor="admin", options={"credential_expires_on": "2026-11-30"})
