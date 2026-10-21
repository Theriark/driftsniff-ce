"""The real property tests keep the default settings of the active Hypothesis profile.

The budget tests in ``test_diff_properties.py`` run *copies* of the property bodies, so they
would stay green if somebody put ``@settings(max_examples=20)`` on a real test. This module
reads the settings that Hypothesis stored on every real property test and compares them with
the profile that is active (500 examples in ``ci``, 5000 in ``nightly``).
"""

from collections.abc import Callable
from typing import Any, Final

from hypothesis import given, settings
from hypothesis import strategies as st

from . import test_diff_properties as real

CHECKED_FIELDS: Final = (
    "max_examples",
    "derandomize",
    "deadline",
    "database",
    "print_blob",
    "suppress_health_check",
)
EXPECTED_PROPERTY_TESTS: Final = 5


def _property_tests() -> dict[str, Callable[..., Any]]:
    return {
        name: member
        for name, member in vars(real).items()
        if name.startswith("test_") and hasattr(member, "hypothesis")
    }


def _stored_settings(test: Callable[..., Any]) -> Any:
    stored = getattr(test, "_hypothesis_internal_use_settings", None)
    assert stored is not None, "Hypothesis no longer stores settings on the test; update this guard"
    return stored


def overrides(test: Callable[..., Any]) -> list[str]:
    """The settings fields in which ``test`` differs from the active profile."""
    stored = _stored_settings(test)
    active = settings()
    return [field for field in CHECKED_FIELDS if getattr(stored, field) != getattr(active, field)]


def test_the_real_property_tests_are_found() -> None:
    assert len(_property_tests()) >= EXPECTED_PROPERTY_TESTS, sorted(_property_tests())


def test_no_real_property_test_overrides_the_profile_settings() -> None:
    found = {name: overrides(test) for name, test in _property_tests().items()}
    assert {name: fields for name, fields in found.items() if fields} == {}


def test_the_guard_flags_an_override() -> None:
    @settings(max_examples=7)
    @given(value=st.integers())
    def overridden(value: int) -> None:
        assert isinstance(value, int)

    @given(value=st.integers())
    def plain(value: int) -> None:
        assert isinstance(value, int)

    assert overrides(overridden) == ["max_examples"]
    assert overrides(plain) == []
