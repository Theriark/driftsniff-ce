"""QNAP XML answers turned into the raw objects of each resource.

QNAP answers with XML (a ``QDocRoot`` document, values mostly in CDATA). The body comes from the
controller, so it is parsed defensively with the standard library only (no new dependency):

* a document type declaration is refused outright, and with it every entity definition, so no
  entity can expand (billion laughs) or point outside (XXE); external entity references and
  parameter entities are refused as well;
* the body was already capped by the client (``MAX_XML_BYTES``) before it gets here;
* every failure is a :class:`CollectorError` of class ``bad_payload`` with a fixed text: the body
  never appears in it.

Each resource keeps only the fields named below; counters, temperatures, usage, uptime, free space
and run states are never taken, so they cannot raise changes. Every element name is UNVERIFIED
(docs/vendor-notes/qnap.md). An element that is missing is left out of the object, never invented.
Objects are sorted by their key; two objects with the same key fail the resource.
"""

import re
from collections.abc import Callable
from typing import Final, NoReturn
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

from driftsniff.collectors.base import ERROR_BAD_PAYLOAD, CollectorError
from driftsniff.core.canonical import JsonValue

ROOT_TAG: Final = "QDocRoot"
SYSTEM_KEY: Final = "system"
WEB_KEY: Final = "web"

_NOT_XML: Final = "the answer is not a QNAP XML document"
_DOCTYPE: Final = "the answer holds a document type declaration, which is refused"
_DUPLICATE: Final = "two objects of the answer have the same key"
_NO_KEY: Final = "an object of the answer has no usable key"

_INTERFACE_FIELDS: Final = (
    "dname",
    "eth_ip",
    "eth_mask",
    "eth_mac",
    "eth_usage",
    "eth_max_speed",
)
_VOLUME_FIELDS: Final = (
    "volumeValue",
    "volumeLabel",
    "volumeStat",
    "volumeDisks",
    "volumeType",
    "encryptfs_bool",
    "is_default_volume",
)
# The flags of the login page answer (nmap http-qnap-nas-info reads the same names).
WEB_FIELDS: Final = (
    "forceSSL",
    "stunnelPort",
    "webFSEnabled",
    "QMultimediaEnabled",
    "MSV2WebEnabled",
    "QDownloadEnabled",
    "NVREnabled",
    "WFM2",
    "QMusicsEnabled",
    "QVideosEnabled",
    "QPhotosEnabled",
    "QWebEnabled",
    "QWebPort",
    "QWebSSLEnabled",
    "QWebSSLPort",
)
_APP_FIELDS: Final = (
    "displayName",
    "version",
    "build",
    "enable",
    "provider",
    "author",
    "class",
    "store",
    "unofficial",
    "code_signing_status",
    "installPath",
    "servPort",
    "webPort",
    "webSSLPort",
)
_IFNAME: Final = re.compile(r"ifname(\d{1,3})")

Objects = list[dict[str, JsonValue]]


class _Refused(Exception):
    """Raised from inside the parser for a declaration the collector does not accept."""


def _refuse(*_: object) -> NoReturn:
    raise _Refused


def parse_document(body: bytes) -> Element:
    """The root element of a QNAP answer; raises ``bad_payload`` for anything else."""
    builder = TreeBuilder()
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.ExternalEntityRefHandler = _refuse
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data
    parser.buffer_text = True
    try:
        parser.Parse(body, True)
        root = builder.close()
    except _Refused:
        raise CollectorError(ERROR_BAD_PAYLOAD, _DOCTYPE) from None
    except (expat.ExpatError, AssertionError, ValueError):
        raise CollectorError(ERROR_BAD_PAYLOAD, _NOT_XML) from None
    if root.tag != ROOT_TAG:
        raise CollectorError(ERROR_BAD_PAYLOAD, _NOT_XML)
    return root


def text_of(element: Element, tag: str) -> str | None:
    """The stripped text of the first element ``tag`` at or below ``element``, None if absent."""
    found = next(element.iter(tag), None)
    if found is None:
        return None
    return "".join(found.itertext()).strip()


def _pick(element: Element, names: tuple[str, ...], suffix: str = "") -> dict[str, JsonValue]:
    picked: dict[str, JsonValue] = {}
    for name in names:
        value = text_of(element, f"{name}{suffix}")
        if value is not None:
            picked[name] = value
    return picked


def _keyed(objects: Objects, key: str) -> Objects:
    seen: set[str] = set()
    for item in objects:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            raise CollectorError(ERROR_BAD_PAYLOAD, _NO_KEY)
        if value in seen:
            raise CollectorError(ERROR_BAD_PAYLOAD, _DUPLICATE)
        seen.add(value)
    return sorted(objects, key=lambda item: str(item[key]))


def _unique(values: list[str]) -> list[JsonValue]:
    """Non-empty values without repeats, first seen first (QNAP repeats DNS entries)."""
    return list(dict.fromkeys(value for value in values if value))


def firmware_version(root: Element) -> str | None:
    """The firmware version of a system information answer (the probe reports it)."""
    firmware = next(root.iter("firmware"), None)
    return None if firmware is None else text_of(firmware, "version") or None


def system(root: Element) -> Objects:
    """The one system object: name, model, firmware, time zone and DNS servers."""
    item: dict[str, JsonValue] = {"id": SYSTEM_KEY}
    hostname = text_of(root, "hostname")
    if hostname is not None:
        item["hostname"] = hostname
    model = text_of(root, "displayModelName")
    if model is not None:
        item["model"] = model
    firmware = next(root.iter("firmware"), None)
    if firmware is not None:
        item["firmware"] = dict(_pick(firmware, ("version", "build", "patch")))
    timezone = text_of(root, "timezone")
    if timezone is not None:
        item["timezone"] = timezone
    dns = [("".join(node.itertext())).strip() for node in root.iter("DNS_LIST")]
    if dns:
        item["dnsServers"] = _unique(dns)
    return [item]


def network_interfaces(root: Element) -> Objects:
    """One object per adapter (``ifname<N>`` with its numbered siblings)."""
    objects: Objects = []
    for node in root.iter():
        match = _IFNAME.fullmatch(str(node.tag))
        if match is None:
            continue
        number = match.group(1)
        item: dict[str, JsonValue] = {"ifname": "".join(node.itertext()).strip()}
        item.update(_pick(root, _INTERFACE_FIELDS, number))
        ipv6 = next(root.iter(f"eth_ipv6_info{number}"), None)
        if ipv6 is not None and (enabled := text_of(ipv6, "eth_ipv6_enable")) is not None:
            item["eth_ipv6_enable"] = enabled
        dns_info = next(root.iter(f"dnsinfo{number}"), None)
        if dns_info is not None:
            item["dns"] = _unique(["".join(child.itertext()).strip() for child in dns_info])
        objects.append(item)
    return _keyed(objects, "ifname")


def volumes(root: Element) -> Objects:
    """One object per volume of ``volumeList``."""
    return _keyed([_pick(volume, _VOLUME_FIELDS) for volume in root.iter("volume")], "volumeValue")


def shared_folders(root: Element) -> Objects:
    """One object per shared folder of ``volumeUseList``, with the volume it lives on."""
    objects: Objects = []
    for use in root.iter("volumeUse"):
        volume = text_of(use, "volumeValue")
        for folder in use.iter("folder_element"):
            item = _pick(folder, ("sharename", "type"))
            if volume is not None:
                item["volumeValue"] = volume
            objects.append(item)
    return _keyed(objects, "sharename")


def web_services(root: Element) -> Objects:
    """The one object of the web interface flags the login page reports."""
    item: dict[str, JsonValue] = {"id": WEB_KEY}
    item.update(_pick(root, WEB_FIELDS))
    return [item]


def apps(root: Element) -> Objects:
    """One object per installed app (``qItem``), keyed by its package name."""
    objects: Objects = []
    for entry in root.iter("qItem"):
        item: dict[str, JsonValue] = {}
        name = entry.findtext("name")
        if name is not None:
            item["name"] = name.strip()
        attributes = entry.find("attr")
        if attributes is not None:
            item.update(_pick(attributes, _APP_FIELDS))
        objects.append(item)
    return _keyed(objects, "name")


EXTRACTORS: Final[dict[str, Callable[[Element], Objects]]] = {
    "qnap-system": system,
    "qnap-network-interfaces": network_interfaces,
    "qnap-volumes": volumes,
    "qnap-shared-folders": shared_folders,
    "qnap-web-services": web_services,
    "qnap-apps": apps,
}
