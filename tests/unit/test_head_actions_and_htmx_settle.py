"""Two findings of the browser check on Development (THE-1043, fixed in THE-1096).

1. htmx 2 copies class, style, width and height across a swap by default. The content security
   policy allows no inline style, so each copied style attribute was a violation in the console:
   the shell configures htmx to settle class, width and height only.
2. app.css hides the actions of a summary head from 1024 px up, because the change detail
   repeats them in its side column. The source page has no side column, so Run now, Edit and
   Disable were gone on a desktop: it marks its head ``summary-head--wrap`` and loads
   ``static/summary-head.css``, which puts the actions back at every width.
"""

import json
import re
from pathlib import Path

from driftsniff.web.csrf import CONTENT_SECURITY_POLICY
from driftsniff.web.templating import TEMPLATES_DIR, Shell, make_environment

TEMPLATES = Path(TEMPLATES_DIR)
STATIC = TEMPLATES.parent / "static"

# the change detail repeats the head actions in its side column, so only it may hide them
HIDES_HEAD_ACTIONS = {"changes/detail.html"}


def test_htmx_never_settles_a_style_attribute_the_policy_refuses() -> None:
    assert "style-src 'self'" in CONTENT_SECURITY_POLICY
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
    source = '{% extends "base.html" %}{% block content %}<p>Body</p>{% endblock %}'
    page = make_environment().from_string(source).render(shell=Shell(title="Changes"))
    match = re.search(r"<meta name=\"htmx-config\" content='([^']*)'>", page)
    assert match is not None, "no htmx-config meta"
    config = json.loads(match.group(1))
    assert config["attributesToSettle"] == ["class", "width", "height"]


def test_the_summary_head_sheet_shows_the_actions_on_a_wide_screen() -> None:
    text = (STATIC / "summary-head.css").read_text(encoding="utf-8")
    assert "#" not in text  # the tokens of app.css only, no colour of its own
    wide = text.split("@media (min-width: 1024px)", 1)
    assert len(wide) == 2, "no wide-screen block"
    block = wide[1].split("}", 2)[0]
    assert ".summary-head--wrap .page-header__actions" in block
    assert "display: flex" in block


def test_the_source_page_keeps_its_head_actions_on_a_wide_screen() -> None:
    text = (TEMPLATES / "sources" / "detail.html").read_text(encoding="utf-8")
    assert '<div class="summary-head summary-head--wrap">' in text
    head = re.search(r"{% block head %}(.*?){% endblock %}", text, re.S)
    assert head is not None, "the source page loads no sheet of its own"
    assert '<link rel="stylesheet" href="/static/summary-head.css">' in head.group(1)


def test_no_page_without_a_side_column_hides_its_head_actions() -> None:
    heads = re.compile(r'class="summary-head(?P<more>(?: [^"]*)?)"')
    found = 0
    for path in sorted(TEMPLATES.rglob("*.html")):
        name = path.relative_to(TEMPLATES).as_posix()
        for match in heads.finditer(path.read_text(encoding="utf-8")):
            found += 1
            if name not in HIDES_HEAD_ACTIONS:
                assert "summary-head--wrap" in match.group("more").split(), name
    assert found >= 3  # the change detail, the source page and the shared history head
