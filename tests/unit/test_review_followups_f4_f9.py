"""THE-1416: the deferred findings F4, F5 (390 px), F6, F7 and F9 of the THE-1402 review.

Found on Development (d9efea98, still on 95b298bf): the change detail's before and after values
sat on red and green tints whatever the risk, with the changed part underlined like a link (F4);
at 390 px the top bar's Add source took a row of its own (F5), section heads squeezed beside
their hint and the source tabs wrapped Configuration onto a second row (F6); the source list
promised a strip the narrow table hides, and its strip scrolled with no end labels (F7); the
signed-out footer started 32 px left of the logo at 1440 px (F9). The rendered checks live on
Development; these pin the stylesheet, token and template rules. Each test fails on 95b298bf.
"""

import json
import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
WEB = REPOSITORY / "src" / "driftsniff" / "web"
TOKENS = REPOSITORY / "docs" / "design-colours.json"


def _css(name: str) -> str:
    css = (WEB / "static" / name).read_text(encoding="utf-8")
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


def _rules(selector: str, media: str = "", sheet: str = "app.css") -> str:
    """The joined bodies of the rules for the selector, at the top level or in the media block."""
    css = _css(sheet)
    scopes = [css] if not media else [b for h, b in _blocks(css) if h == f"@media {media}"]
    return "".join(
        body
        for scope in scopes
        for head, body in _blocks(scope)
        if not head.startswith("@") and selector in [part.strip() for part in head.split(",")]
    )


# ---- F4: the change detail's before and after ------------------------------------------------


def test_before_and_after_sit_on_neutral_tints_in_both_themes() -> None:
    """Red stays for critical items and failures: a tint is neutral when its three channels
    are within a few steps of each other (the old #F7D9D6 and #DDEBDD were 33 and 14 apart)."""
    themes = json.loads(TOKENS.read_text(encoding="utf-8"))["themes"]
    for theme in ("light", "dark"):
        for token in ("diff-removed", "diff-added"):
            value = themes[theme][token]
            channels = [int(value[i : i + 2], 16) for i in (1, 3, 5)]
            assert max(channels) - min(channels) <= 10, f"{theme} {token} {value} has a hue"


def test_the_changed_part_is_boxed_not_underlined_like_a_link() -> None:
    mark = _rules(".diff mark")
    assert "underline" not in mark
    assert re.search(r"border:\s*1px solid var\(--slate\);", mark)
    assert re.search(r"background:\s*var\(--surface\);", mark)
    # the hairline is a checked graphic pair on both tints, in both themes
    checks = json.loads(TOKENS.read_text(encoding="utf-8"))["checks"]
    pairs = {(c["theme"], c["foreground"], c["background"]) for c in checks}
    for theme in ("light", "dark"):
        for tint in ("diff-removed", "diff-added"):
            assert (theme, "slate", tint) in pairs, (theme, tint)


# ---- F5: the top bar action on a phone ------------------------------------------------------


def test_on_a_phone_the_top_bar_action_keeps_its_icon_and_hides_its_label() -> None:
    button = _rules(".topbar__action", "(max-width: 479px)")
    assert re.search(r"width:\s*40px;", button)
    assert re.search(r"padding:\s*0;", button)
    # the hidden label stays inside the button instead of widening the page
    assert re.search(r"position:\s*relative;", button)
    label = _rules(".topbar__action-label", "(max-width: 479px)")
    assert re.search(r"clip:\s*rect\(0 0 0 0\);", label)
    assert re.search(r"position:\s*absolute;", label)
    # wider screens keep the words: the label has no rule outside the phone block
    assert _rules(".topbar__action-label") == ""
    base = (WEB / "templates" / "base.html").read_text(encoding="utf-8")
    assert '<span class="topbar__action-label">{{ action[0] }}</span></a>' in base


# ---- F6: section heads and the source tabs at 390 px ----------------------------------------


def test_a_section_head_drops_its_hint_under_the_heading_instead_of_squeezing() -> None:
    head = _rules(".section-head")
    assert re.search(r"flex-wrap:\s*wrap;", head)
    assert re.search(r"gap:\s*var\(--sp-1\) var\(--sp-4\);", head)


def test_on_a_phone_the_five_source_tabs_fit_one_row_of_a_390_px_screen() -> None:
    """The labels are about 301 px at 14 px bold; four 12 px gaps make 349 of the 354 px."""
    tabs = _rules(".tabs ul", "(max-width: 767px)", sheet="summary-head.css")
    assert re.search(r"gap:\s*0 var\(--sp-3\);", tabs)
    # still wraps on a narrower phone rather than hiding a tab past the edge
    assert re.search(r"flex-wrap:\s*wrap;", tabs)


# ---- F7: the source list strip --------------------------------------------------------------


def test_the_source_list_strip_keeps_its_end_labels() -> None:
    assert "display: none" not in _rules(".drift-cell .driftline__axis")
    assert re.search(r"direction:\s*rtl;", _rules(".driftline__strip"))


def test_the_source_list_summary_does_not_promise_a_strip_a_narrow_screen_hides() -> None:
    listing = (WEB / "templates" / "sources" / "list.html").read_text(encoding="utf-8")
    assert "the strip shows" not in listing
    assert "Status follows the last check.</p>" in listing
    # the column that the summary no longer describes still names its 30 days, and hides
    assert '{"label": "Drift line, last 30 days", "class": "col-hide-m"}' in listing


# ---- F9: the signed-out footer edge ---------------------------------------------------------


def test_the_footer_text_starts_on_the_same_edge_as_the_header_and_the_page() -> None:
    """The gutter sits inside the 1280 px column, as it does for .app-header__inner and .page."""
    footer = _rules(".app-footer")
    assert re.search(r"padding:\s*var\(--sp-4\) 0;", footer)
    inner = _rules(".app-footer__inner")
    assert re.search(r"max-width:\s*var\(--content-max\);", inner)
    assert re.search(r"padding:\s*0 var\(--gutter\);", inner)
    header = _rules(".app-header__inner")
    assert re.search(r"max-width:\s*var\(--content-max\);", header)
    assert re.search(r"padding:\s*0 var\(--gutter\);", header)
