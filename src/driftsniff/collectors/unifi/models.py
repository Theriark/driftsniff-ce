"""What the UniFi collector reads through pydantic: the paging envelope and the object key.

Everything else stays a raw dictionary on purpose (dev work plan, decision 1): an unknown field
must reach the type table and become unclassified, never be dropped by a model. The envelope names
(``data``, ``totalCount`` and so on) are **unverified** against the vendor reference (dependency D5
is open, docs/vendor-notes/unifi.md).

A validation error of pydantic repeats the offending input, so the collector never shows one: it
catches :class:`pydantic.ValidationError` and raises a fixed text instead.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class PageEnvelope(BaseModel):
    """One page of a list answer: the objects and, when the controller says so, the total."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    data: list[dict[str, Any]]
    offset: StrictInt | None = None
    limit: StrictInt | None = None
    count: StrictInt | None = None
    total_count: StrictInt | None = Field(default=None, alias="totalCount")


class ObjectRef(BaseModel):
    """The key and the name of an object, read from the raw dictionary and nothing else."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=128)
    name: str | None = None


class InfoAnswer(BaseModel):
    """The answer of the information call: only the application version is read."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    application_version: str = Field(alias="applicationVersion", min_length=1, max_length=64)
