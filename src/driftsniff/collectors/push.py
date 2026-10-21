"""The push source: a collector that reads what a sender posted instead of calling a controller.

A sender posts one JSON document that maps resource names to lists of objects. The endpoint
(``driftsniff.web.routes_push``) checks the sender key and the size, parses the body with
:func:`parse_push_body` and hands the result to :class:`PushCollector`, which gives it to the
same run pipeline a polled source uses (docs/push.md has the user view).

The admin declares, per resource, the top-level fields that are configuration. The collector
keeps only those fields of every object. Everything else the sender included never reaches the
pipeline, so it can neither be stored nor become an unclassified change. A resource the admin
did not declare is ignored as a whole, and a resource missing from the body keeps its previous
state in the pipeline; it is never reported as removed.

Parse errors carry fixed texts: the body, a field name or a value never appears in one.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Final

from driftsniff.collectors.base import Collector, FetchResult, ResourceSpec
from driftsniff.core.canonical import JsonValue

MAX_PUSH_BODY_BYTES: Final = 10 * 1024 * 1024
PUSH_HEADER: Final = "X-Driftsniff-Push-Key"

PushDocument = dict[str, list[dict[str, JsonValue]]]


class PushBodyError(ValueError):
    """The body of a push is not a JSON object of resource names to lists of objects."""


def _no_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise PushBodyError("the body repeats a key in one object")
        result[key] = value
    return result


def _no_constants(_name: str) -> JsonValue:
    raise PushBodyError("the body holds NaN or Infinity, which JSON does not allow")


def parse_push_body(raw: bytes) -> PushDocument:
    """Parse a push body: an object of resource names to lists of objects.

    Raises :class:`PushBodyError` for anything else, including NaN, Infinity, a key repeated in
    one object and a document nested too deeply to read.
    """
    try:
        parsed = json.loads(raw, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants)
    except PushBodyError:
        raise
    except RecursionError:
        raise PushBodyError("the body is nested too deeply") from None
    except ValueError:
        raise PushBodyError("the body is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise PushBodyError("the body must be an object that maps resource names to lists")
    document: PushDocument = {}
    for name, objects in parsed.items():
        if not isinstance(objects, list):
            raise PushBodyError("every resource must be a list of objects")
        items: list[dict[str, JsonValue]] = []
        for entry in objects:
            if not isinstance(entry, dict):
                raise PushBodyError("every resource must be a list of objects")
            items.append(entry)
        document[name] = items
    return document


class PushCollector(Collector):
    """Hands the declared fields of the pushed objects to the run pipeline.

    ``fields`` is the allow-list of the source (resource to top-level field names). One instance
    serves one run. ``body_bytes`` is the size of the posted body; it is reported as the bytes
    fetched by the first resource, so the run record shows what was received.
    """

    def __init__(
        self,
        document: Mapping[str, Sequence[Mapping[str, JsonValue]]],
        fields: Mapping[str, Sequence[str]],
        *,
        body_bytes: int = 0,
    ) -> None:
        self._document = document
        self._fields = {resource: frozenset(names) for resource, names in fields.items()}
        self._bytes_unreported = body_bytes

    @property
    def ignored_resources(self) -> int:
        """How many resources of the body the admin did not declare."""
        return sum(1 for name in self._document if name not in self._fields)

    def probe(self) -> str | None:
        """A pushed document carries no controller version."""
        return None

    def resources(self) -> Sequence[ResourceSpec]:
        """The declared resources that the body contains, in name order."""
        return [ResourceSpec(name) for name in sorted(self._document) if name in self._fields]

    def fetch(self, spec: ResourceSpec) -> FetchResult:
        """The objects of one resource, cut down to its declared fields."""
        allowed = self._fields[spec.name]
        kept = [
            {field: value for field, value in entry.items() if field in allowed}
            for entry in self._document[spec.name]
        ]
        reported, self._bytes_unreported = self._bytes_unreported, 0
        return FetchResult.success(kept, bytes_fetched=reported)
