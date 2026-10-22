"""Template scan (P9-T2): no template may switch off escaping, and no code may build an
environment with autoescape off. P10 adds the templates; this test is already in place."""

import re
from pathlib import Path

import pytest

import driftsniff

PACKAGE = Path(driftsniff.__file__).parent
TEMPLATES = PACKAGE / "web" / "templates"
TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".xml", ".svg", ".txt"}

_UNSAFE_TEMPLATE = (
    (re.compile(r"\|\s*safe\b"), "the safe filter"),
    (re.compile(r"\{%-?\s*autoescape\s+(false|off)\b", re.IGNORECASE), "an autoescape off block"),
)
_UNSAFE_CODE = re.compile(r"autoescape\s*=\s*False")


def unsafe_markers(text: str) -> list[str]:
    """The unsafe constructs found in one template."""
    return [label for pattern, label in _UNSAFE_TEMPLATE if pattern.search(text)]


def test_the_scan_finds_the_unsafe_constructs() -> None:
    assert unsafe_markers("<p>{{ note | safe }}</p>") == ["the safe filter"]
    assert unsafe_markers("{{ note|safe}}") == ["the safe filter"]
    assert unsafe_markers("{% autoescape false %}{{ x }}{% endautoescape %}") == [
        "an autoescape off block"
    ]
    assert unsafe_markers("{%- autoescape off -%}") == ["an autoescape off block"]


def test_the_scan_leaves_safe_templates_alone() -> None:
    assert unsafe_markers("<p>{{ note }}</p>") == []
    assert unsafe_markers("{% autoescape true %}{{ note }}{% endautoescape %}") == []
    assert unsafe_markers("{{ note | e }} {{ safety }} {{ x | safely }}") == []


def test_the_scan_of_code_finds_a_switched_off_environment() -> None:
    assert _UNSAFE_CODE.search("Environment(loader=x, autoescape=False)")
    assert not _UNSAFE_CODE.search("Environment(loader=x, autoescape=select_autoescape())")


def _templates() -> list[Path]:
    if not TEMPLATES.is_dir():
        return []
    return sorted(p for p in TEMPLATES.rglob("*") if p.suffix.lower() in TEMPLATE_SUFFIXES)


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.name)
def test_no_template_uses_an_unsafe_marker(path: Path) -> None:
    assert unsafe_markers(path.read_text(encoding="utf-8")) == []


def test_no_code_builds_a_template_environment_with_autoescape_off() -> None:
    offenders = [
        str(path.relative_to(PACKAGE))
        for path in PACKAGE.rglob("*.py")
        if _UNSAFE_CODE.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
