"""Fixtures of the security suite."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from .appkit import Kit, running_kit


@pytest.fixture
def kit(tmp_path: Path) -> Iterator[Kit]:
    """The complete application of ``appkit`` on a fresh database."""
    with running_kit(tmp_path) as built:
        yield built
