"""The collector factory: a collector from a stored source or from the values of a form (P10).

Two entry points share one builder:

* :meth:`CollectorFactory.for_source` is the ``collector_factory`` of the scheduler. It reads the
  stored source, decrypts its credential and builds the collector of its type. A source that
  cannot be turned into a collector (a credential that cannot be decrypted, a CA file that is
  gone, a settings combination the collector refuses) still gets a collector: one whose probe
  fails with a fixed text, so the run record says why instead of the scheduler failing silently.
* :meth:`CollectorFactory.for_target` is the :data:`~driftsniff.sources.probe.ProbeFactory` of the
  test connection button. It builds the collector from the values of the form and raises for
  values it cannot use; ``start_probe`` turns that into a ``not_started`` result.

Both pass the TLS settings of the source (``tls_mode``, ``tls_ca_file``, ``tls_pin``; the mode
``insecure`` sets the flag the TLS check wants), ``allow_plain_http`` and, for Xen Orchestra, the
credential expiry the admin entered. Both wrap the collector so that the resources in the
``resources_off`` option are not listed and therefore never requested; the run pipeline keeps
the stored state of a resource that a run did not read, so turning one off removes nothing.

A push source has no collector here: its collector is made per request by the push endpoint from
the posted document.

The credential is handed to the collector and to nothing else. Texts of the unavailable
collector are fixed, and a text that would hold the credential is replaced by a fixed sentence.
"""

import logging
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Final

from driftsniff.collectors.base import Collector, CollectorError, FetchResult, ResourceSpec
from driftsniff.collectors.tls import (
    MODE_INSECURE,
    OPTION_INSECURE,
    OPTION_TLS_MODE,
    TLS_OPTIONS,
    TlsSettings,
    check_options,
)
from driftsniff.collectors.unifi.client import UnifiClient
from driftsniff.collectors.xo.client import XoClient
from driftsniff.config import DEFAULT_DATA_DIR
from driftsniff.secrets.crypto import CredentialCryptoError
from driftsniff.sources.probe import ProbeTarget
from driftsniff.sources.service import (
    OPTION_ALLOW_PLAIN_HTTP,
    OPTION_CREDENTIAL_EXPIRES_ON,
    OPTION_RESOURCES_OFF,
    POLLED_TYPES,
    SourceService,
    SourceView,
)

logger = logging.getLogger(__name__)

ERROR_RESOURCE_OFF: Final = "resource_off"
ERROR_NO_CREDENTIAL: Final = "no_credential"
ERROR_CREDENTIAL_UNREADABLE: Final = "credential_unreadable"
ERROR_NOT_STARTED: Final = "not_started"

_NO_CREDENTIAL_TEXT: Final = "the source has no credential stored; enter one on the edit page"
_UNREADABLE_TEXT: Final = "the stored credential cannot be read; enter it again on the edit page"
_NOT_STARTED_TEXT: Final = "the source settings cannot be used"
_HIDDEN_TEXT: Final = "the source settings cannot be used (the text was hidden)"


def resources_turned_off(options: Mapping[str, object]) -> frozenset[str]:
    """The resources the admin turned off in the ``resources_off`` option of a source."""
    value = options.get(OPTION_RESOURCES_OFF)
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(name) for name in value)


class ResourceFilter(Collector):
    """A collector that does not list, and never reads, the resources turned off."""

    def __init__(self, inner: Collector, off: frozenset[str]) -> None:
        self._inner = inner
        self._off = off

    def probe(self) -> str | None:
        return self._inner.probe()

    def resources(self) -> Sequence[ResourceSpec]:
        return [spec for spec in self._inner.resources() if spec.name not in self._off]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        if spec.name in self._off:
            return FetchResult.failure(ERROR_RESOURCE_OFF, "the resource is turned off")
        return self._inner.fetch(spec)

    def close(self) -> None:
        self._inner.close()


class UnavailableCollector(Collector):
    """What a source gets when its collector cannot be built: the probe fails with a fixed text.

    The run pipeline records that failure as the run, so the source page shows the reason.
    """

    def __init__(self, error_class: str, text: str) -> None:
        self._error_class = error_class
        self._text = text

    def probe(self) -> str | None:
        raise CollectorError(self._error_class, self._text)

    def resources(self) -> Sequence[ResourceSpec]:
        return []

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        raise CollectorError(self._error_class, self._text)


def _tls_settings(options: Mapping[str, object]) -> TlsSettings | None:
    """The TLS settings of the options, or None when the source has no TLS option.

    The form does not set the flag ``insecure``; the source service does when it stores the mode.
    It is set here the same way, so a form that is being tested is read like the stored source.
    """
    if not any(key in options for key in TLS_OPTIONS):
        return None
    checked = {key: options[key] for key in TLS_OPTIONS if key in options}
    if checked.get(OPTION_TLS_MODE) == MODE_INSECURE:
        checked[OPTION_INSECURE] = True
    else:
        checked.pop(OPTION_INSECURE, None)
    if options.get(OPTION_ALLOW_PLAIN_HTTP) is True:
        checked[OPTION_ALLOW_PLAIN_HTTP] = True
    return check_options(checked)


def _expiry(options: Mapping[str, object]) -> date | None:
    value = options.get(OPTION_CREDENTIAL_EXPIRES_ON)
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _secret(credential: bytes) -> str:
    try:
        return credential.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ValueError("the credential is not text") from None


def build_collector(
    source_type: str,
    base_url: str | None,
    credential: bytes,
    options: Mapping[str, object],
    *,
    data_dir: Path | str = DEFAULT_DATA_DIR,
) -> Collector:
    """The collector of a ``unifi`` or ``xo`` source, with its resources turned off removed.

    Raises ``ValueError`` (fixed texts) for an address, credential or TLS setting the collector
    refuses.
    """
    if source_type not in POLLED_TYPES:
        raise ValueError("only a unifi or xo source is read from a controller")
    if base_url is None:
        raise ValueError("the source has no address")
    secret = _secret(credential)
    plain = options.get(OPTION_ALLOW_PLAIN_HTTP) is True
    tls = _tls_settings(options)
    inner: Collector
    if source_type == "unifi":
        inner = UnifiClient(base_url, secret, allow_plain_http=plain, tls=tls, data_dir=data_dir)
    else:
        inner = XoClient(
            base_url,
            secret,
            allow_plain_http=plain,
            tls=tls,
            data_dir=data_dir,
            expires_on=_expiry(options),
        )
    off = resources_turned_off(options)
    return ResourceFilter(inner, off) if off else inner


def _safe_text(error: Exception, credential: bytes) -> str:
    """The message of a refusal, unless it would carry the credential."""
    text = " ".join(str(error).split())
    secret = credential.decode("utf-8", errors="replace").strip()
    if not text:
        return _NOT_STARTED_TEXT
    if secret and secret in text:
        return _HIDDEN_TEXT
    return text


class CollectorFactory:
    """Builds the collectors of one installation: its source service and its data folder."""

    def __init__(self, service: SourceService, data_dir: Path | str = DEFAULT_DATA_DIR) -> None:
        self._service = service
        self._data_dir = data_dir

    def for_source(self, view: SourceView) -> Collector:
        """The collector for one run of a stored source (the scheduler's factory).

        ``SourceNotFoundError`` is not caught: the scheduler ends the task of a deleted source.
        """
        credential = self._read_credential(view.id)
        if credential is None:
            return UnavailableCollector(ERROR_NO_CREDENTIAL, _NO_CREDENTIAL_TEXT)
        if not credential:
            return UnavailableCollector(ERROR_CREDENTIAL_UNREADABLE, _UNREADABLE_TEXT)
        try:
            return build_collector(
                view.type, view.base_url, credential, view.options, data_dir=self._data_dir
            )
        except ValueError as error:
            logger.warning("source %s: no collector could be made", view.id)
            return UnavailableCollector(ERROR_NOT_STARTED, _safe_text(error, credential))

    def for_target(self, target: ProbeTarget) -> Collector:
        """The collector of a test connection, from the values of a form.

        Raises ``ValueError`` for values that cannot be used; ``start_probe`` reports that.
        """
        return build_collector(
            target.source_type,
            target.base_url,
            target.credential,
            target.options,
            data_dir=self._data_dir,
        )

    def _read_credential(self, source_id: int) -> bytes | None:
        """The decrypted credential, None when none is stored, ``b""`` when it cannot be read."""
        try:
            return self._service.credential_for_collector(source_id)
        except CredentialCryptoError:
            logger.warning("source %s: the stored credential cannot be decrypted", source_id)
            return b""
