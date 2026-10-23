"""The collector factory (sources/factory.py): the collector of a stored source or a form.

Nothing here talks to a controller: the collectors are only built and asked what they would read.
The reads themselves are in ``tests/contract/test_collection_wiring.py``. Every secret is a
synthetic ``CANARY-`` value.
"""

from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from driftsniff.collectors.base import Collector, CollectorError, FetchResult, ResourceSpec
from driftsniff.collectors.tls import INSECURE_CONFIRMATION
from driftsniff.collectors.unifi.client import UnifiClient
from driftsniff.collectors.xo.client import XoClient
from driftsniff.db.engine import Database, database_path
from driftsniff.db.migrate import upgrade_to_head
from driftsniff.secrets.crypto import CredentialCipher
from driftsniff.secrets.keys import MasterKey
from driftsniff.sources import factory as factory_module
from driftsniff.sources.factory import (
    ERROR_CREDENTIAL_UNREADABLE,
    ERROR_NO_CREDENTIAL,
    ERROR_NOT_STARTED,
    ERROR_RESOURCE_OFF,
    CollectorFactory,
    ResourceFilter,
    UnavailableCollector,
    resources_turned_off,
)
from driftsniff.sources.probe import ProbeTarget, start_probe
from driftsniff.sources.service import SourceService, SourceView

ADDRESS = "https://203.0.113.10:8443"
ACTOR = "admin"
CANARY = "CANARY-factory-credential-0001"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Database]:
    database = Database(database_path(tmp_path))
    try:
        upgrade_to_head(database)
        yield database
    finally:
        database.close()


@pytest.fixture
def service(store: Database) -> SourceService:
    return SourceService(store, CredentialCipher.from_master(MasterKey(bytes(range(32)))))


@pytest.fixture
def factory(service: SourceService, tmp_path: Path) -> CollectorFactory:
    return CollectorFactory(service, tmp_path)


def add(
    service: SourceService,
    source_type: str = "xo",
    *,
    name: str = "lab",
    options: Mapping[str, object] | None = None,
    tls_confirmation: str | None = None,
) -> SourceView:
    return service.create(
        name=name,
        source_type=source_type,
        actor=ACTOR,
        base_url=ADDRESS,
        credential=CANARY,
        options=options,
        tls_confirmation=tls_confirmation,
    )


class Recording(Collector):
    """A collector that lists two resources and counts what it is asked."""

    def __init__(self) -> None:
        self.fetched: list[str] = []
        self.closed = 0

    def probe(self) -> str | None:
        return "1.2.3"

    def resources(self) -> Sequence[ResourceSpec]:
        return [ResourceSpec("one"), ResourceSpec("two")]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        self.fetched.append(spec.name)
        return FetchResult.success([{"id": spec.name}])

    def close(self) -> None:
        self.closed += 1


def names(collector: Collector) -> list[str]:
    return [spec.name for spec in collector.resources()]


# -- the type decides the collector ------------------------------------------------------------


def test_a_unifi_source_gets_the_unifi_collector(
    service: SourceService, factory: CollectorFactory
) -> None:
    collector = factory.for_source(add(service, "unifi"))
    try:
        assert isinstance(collector, UnifiClient)
    finally:
        collector.close()


def test_an_xo_source_gets_the_xo_collector(
    service: SourceService, factory: CollectorFactory
) -> None:
    collector = factory.for_source(add(service, "xo"))
    try:
        assert isinstance(collector, XoClient)
    finally:
        collector.close()


def test_the_credential_expiry_the_admin_entered_reaches_the_xo_collector(
    service: SourceService, factory: CollectorFactory
) -> None:
    view = add(service, "xo", options={"credential_expires_on": "2020-01-01"})
    collector = factory.for_source(view)
    try:
        assert isinstance(collector, XoClient)
        assert collector.token_expiring() is True
    finally:
        collector.close()


def test_every_tls_mode_builds_a_collector(
    service: SourceService, factory: CollectorFactory
) -> None:
    options: list[tuple[Mapping[str, object], str | None]] = [
        ({}, None),
        ({"tls_mode": "pinned", "tls_pin": "ab" * 32}, None),
        ({"tls_mode": "insecure"}, INSECURE_CONFIRMATION),
    ]
    for position, (chosen, confirmation) in enumerate(options):
        view = add(
            service, "unifi", name=f"mode-{position}", options=chosen, tls_confirmation=confirmation
        )
        collector = factory.for_source(view)
        try:
            assert isinstance(collector, UnifiClient)
        finally:
            collector.close()


def test_a_form_in_the_insecure_mode_is_read_like_the_stored_source(
    factory: CollectorFactory,
) -> None:
    # The form does not set the flag the service sets when it stores the mode.
    target = ProbeTarget("xo", ADDRESS, CANARY.encode(), {"tls_mode": "insecure"})
    collector = factory.for_target(target)
    try:
        assert isinstance(collector, XoClient)
    finally:
        collector.close()


def test_a_plain_http_address_needs_the_option_in_a_form_too(factory: CollectorFactory) -> None:
    refused = ProbeTarget("xo", "http://203.0.113.10", CANARY.encode())
    result = start_probe(factory.for_target, refused)
    assert (result.ok, result.error_class) == (False, ERROR_NOT_STARTED)
    assert result.error_text is not None
    assert "allow_plain_http" in result.error_text
    allowed = ProbeTarget("xo", "http://203.0.113.10", CANARY.encode(), {"allow_plain_http": True})
    collector = factory.for_target(allowed)
    collector.close()


def test_a_push_source_has_no_factory_collector(factory: CollectorFactory) -> None:
    result = start_probe(factory.for_target, ProbeTarget("push", ADDRESS, b""))
    assert (result.ok, result.error_class) == (False, ERROR_NOT_STARTED)


def test_a_credential_a_header_cannot_carry_is_refused_without_echoing_it(
    factory: CollectorFactory,
) -> None:
    secret = "CANARY has a space"  # noqa: S105 - a test canary, not a credential
    result = start_probe(factory.for_target, ProbeTarget("unifi", ADDRESS, secret.encode()))
    assert (result.ok, result.error_class) == (False, ERROR_NOT_STARTED)
    assert secret not in (result.error_text or "")


# -- resources turned off are never listed -----------------------------------------------------


def test_the_resources_turned_off_are_read_from_the_option() -> None:
    assert resources_turned_off({}) == frozenset()
    assert resources_turned_off({"resources_off": "vms"}) == frozenset()
    assert resources_turned_off({"resources_off": ["vms", "pools"]}) == {"vms", "pools"}


def test_an_xo_collector_does_not_list_the_resources_turned_off(
    service: SourceService, factory: CollectorFactory
) -> None:
    every = factory.for_source(add(service, "xo", name="all"))
    narrowed = factory.for_source(
        add(service, "xo", name="some", options={"resources_off": ["pools", "vms"]})
    )
    try:
        assert {"pools", "vms"} <= set(names(every))
        assert names(narrowed) == [name for name in names(every) if name not in ("pools", "vms")]
        assert isinstance(narrowed, ResourceFilter)
    finally:
        every.close()
        narrowed.close()


def test_a_unifi_collector_does_not_list_the_resources_turned_off(
    service: SourceService, factory: CollectorFactory
) -> None:
    every = factory.for_source(add(service, "unifi", name="all"))
    narrowed = factory.for_source(
        add(service, "unifi", name="some", options={"resources_off": ["unifi-wans"]})
    )
    try:
        assert "unifi-wans" in names(every)
        assert names(narrowed) == [name for name in names(every) if name != "unifi-wans"]
    finally:
        every.close()
        narrowed.close()


def test_a_form_that_turns_resources_off_is_tested_without_them(
    factory: CollectorFactory,
) -> None:
    target = ProbeTarget("xo", ADDRESS, CANARY.encode(), {"resources_off": ["hosts"]})
    collector = factory.for_target(target)
    try:
        assert "hosts" not in names(collector)
        assert "vms" in names(collector)
    finally:
        collector.close()


def test_the_filter_passes_probe_and_close_on_and_never_fetches_a_resource_turned_off() -> None:
    inner = Recording()
    filtered = ResourceFilter(inner, frozenset({"two"}))
    assert filtered.probe() == "1.2.3"
    assert names(filtered) == ["one"]
    assert filtered.fetch(ResourceSpec("one")).ok
    refused = filtered.fetch(ResourceSpec("two"))
    assert (refused.ok, refused.error_class) == (False, ERROR_RESOURCE_OFF)
    filtered.close()
    assert (inner.fetched, inner.closed) == (["one"], 1)


# -- a source that cannot get a collector still gets a run record ------------------------------


class _NoCredential:
    def credential_for_collector(self, source_id: int) -> bytes | None:
        return None


def view_of(source_type: str = "xo", options: Mapping[str, object] | None = None) -> SourceView:
    return SourceView(
        id=1,
        name="lab",
        type=source_type,
        base_url=ADDRESS,
        options=dict(options or {}),
        enabled=True,
        state="new",
        has_credential=False,
        last_checked_at=None,
        last_success_at=None,
        controller_version=None,
    )


def refusal_of(collector: Collector) -> CollectorError:
    assert isinstance(collector, UnavailableCollector)
    with pytest.raises(CollectorError) as raised:
        collector.probe()
    assert list(collector.resources()) == []
    with pytest.raises(CollectorError):
        collector.fetch(ResourceSpec("vms"))
    return raised.value


def test_a_source_without_a_credential_fails_its_run_with_a_fixed_text(tmp_path: Path) -> None:
    factory = CollectorFactory(cast(SourceService, _NoCredential()), tmp_path)
    refusal = refusal_of(factory.for_source(view_of()))
    assert refusal.error_class == ERROR_NO_CREDENTIAL


def test_a_credential_that_cannot_be_decrypted_fails_its_run_with_a_fixed_text(
    store: Database, service: SourceService, tmp_path: Path
) -> None:
    created = add(service)
    other_key = MasterKey(bytes(reversed(range(32))))
    other = SourceService(store, CredentialCipher.from_master(other_key))
    refusal = refusal_of(CollectorFactory(other, tmp_path).for_source(created))
    assert refusal.error_class == ERROR_CREDENTIAL_UNREADABLE
    assert CANARY not in str(refusal)


def test_a_missing_ca_file_fails_its_run_with_the_reason(
    service: SourceService, factory: CollectorFactory
) -> None:
    view = add(service, options={"tls_mode": "ca_file", "tls_ca_file": "missing.pem"})
    refusal = refusal_of(factory.for_source(view))
    assert refusal.error_class == ERROR_NOT_STARTED
    assert str(refusal) == "the CA file does not exist in the CA folder"


def test_a_refusal_that_would_carry_the_credential_is_replaced(
    service: SourceService, factory: CollectorFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def leaking(*args: object, **kwargs: object) -> Collector:
        raise ValueError(f"cannot use {CANARY}")

    monkeypatch.setattr(factory_module, "build_collector", leaking)
    refusal = refusal_of(factory.for_source(add(service)))
    assert refusal.error_class == ERROR_NOT_STARTED
    assert CANARY not in str(refusal)
