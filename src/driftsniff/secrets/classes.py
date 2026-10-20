"""Field classes: how the product treats one field of a controller object.

Four classes exist (``FieldClass`` lives in :mod:`driftsniff.core.normalize`, which needs it to
drop ignored fields; it is re-exported here because the secrets code is where the classes are
decided and explained):

- ``config``: a setting worth tracking. The value is stored and shown.
- ``secret``: a credential. Only a keyed fingerprint is stored and shown, never the value.
- ``ignore``: volatile data (counters, uptime). Dropped before anything is stored.
- ``unclassified``: a field nobody has classified yet (a new vendor field). It is stored, but a
  change is shown as a fingerprint only, until someone classifies it.

The scanner (:mod:`driftsniff.secrets.scanner`) can force the secret class on a value that
looks like a credential, whatever class its field has.
"""

from driftsniff.core.normalize import FieldClass

__all__ = [
    "FIELD_CLASS_NAMES",
    "FieldClass",
    "is_fingerprinted",
    "is_shown_as_fingerprint",
    "parse_field_class",
]

FIELD_CLASS_NAMES: tuple[str, ...] = tuple(member.value for member in FieldClass)


def parse_field_class(name: str) -> FieldClass:
    """Return the class called ``name`` (as written in a type table); unknown names raise."""
    try:
        return FieldClass(name)
    except ValueError:
        allowed = ", ".join(FIELD_CLASS_NAMES)
        raise ValueError(f"unknown field class {name!r}; use one of: {allowed}") from None


def is_fingerprinted(field_class: FieldClass) -> bool:
    """True when the value never reaches storage: only its fingerprint does."""
    return field_class is FieldClass.SECRET


def is_shown_as_fingerprint(field_class: FieldClass) -> bool:
    """True when a change of this field is displayed as a fingerprint only."""
    return field_class in (FieldClass.SECRET, FieldClass.UNCLASSIFIED)
