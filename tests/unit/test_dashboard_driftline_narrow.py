"""THE-1264 residual: the dashboard's drift line names and its today label at narrow widths.

Found on Development (2c6d22d1, still on df572288) at 390 px: the name and the one-line meta
"Push source, 4 pushes in 30 days" shared a row, the meta took 210 px and left the name 82 px,
so "DEV-FIXTURE synthetic (removable)" read "DEV-FIXT...". At 1024 and 390 px the strip (a
480 px drawing) scrolled inside its cell from the left, so its "today" label and the newest
marks were off-screen. The rendered checks live on Development; these pin the stylesheet rules.
"""

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web"


def _css() -> str:
    css = (WEB / "static" / "app.css").read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _blocks(css: str) -> list[tuple[str, str]]:
    """The top-level blocks of the stylesheet text as (head, body) pairs."""
    blocks, depth, start, body = list[tuple[str, str]](), 0, 0, 0
    head = ""
    for index, char in enumerate(css):
        if char == "{":
            if depth == 0:
                head, body = css[start:index].strip(), index + 1
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                blocks.append((head, css[body:index]))
                start = index + 1
    return blocks


def _rules(selector: str, media: str = "") -> str:
    """The joined bodies of the rules for the selector, at the top level or in the media block."""
    scopes = [_css()] if not media else [b for h, b in _blocks(_css()) if h == f"@media {media}"]
    return "".join(
        body
        for scope in scopes
        for head, body in _blocks(scope)
        if not head.startswith("@") and selector in [part.strip() for part in head.split(",")]
    )


def test_a_drift_line_name_wraps_instead_of_ending_in_an_ellipsis() -> None:
    name = _rules(".driftline__name")
    for clipping in ("nowrap", "ellipsis", "overflow: hidden"):
        assert clipping not in name, clipping
    assert re.search(r"overflow-wrap:\s*anywhere", name)
    assert re.search(r"min-width:\s*0", name)


def test_below_768_px_the_name_meta_and_strip_each_take_the_full_width() -> None:
    """One column, so the name gets the card's width rather than what the meta leaves."""
    row = _rules(".driftlines .driftline", "(max-width: 767px)")
    assert re.search(r"grid-template-columns:\s*minmax\(0, 1fr\);", row)
    # the 768 to 1023 px layout (name and meta side by side, strip below) is unchanged
    tablet = _rules(".driftline", "(max-width: 1023px)")
    assert re.search(r"grid-template-columns:\s*1fr auto;", tablet)


def test_the_desktop_columns_of_the_drift_line_are_unchanged() -> None:
    tracks = re.findall(r"grid-template-columns:\s*([^;]+);", _rules(".driftline"))
    assert tracks == ["160px 150px 1fr"]


def test_a_scrolling_dashboard_strip_opens_at_today() -> None:
    """Right to left, the scroller starts at its right end (today); its content stays left to
    right, so the drawing and the "30 days ago" and "today" labels keep their order."""
    assert re.search(r"direction:\s*rtl;", _rules(".driftlines .driftline__strip"))
    assert re.search(r"direction:\s*ltr;", _rules(".driftlines .driftline__strip > *"))
    strip = _rules(".driftline__strip")
    assert re.search(r"overflow-x:\s*auto;", strip)
    # the strips of the source list and the source page keep their direction
    assert "direction" not in strip
