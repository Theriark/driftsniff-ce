"""The change list's search on a phone (THE-1161, from the THE-1138 acceptance of WP2).

At 390 px the search shared its row with Filters and Apply and was clipped to "Search chang".
Below 440 px of filter bar the search takes a row of its own. The bar is a size container named
filters, so the rule follows the width of the bar, not of the screen.
"""

import re
from pathlib import Path

from driftsniff.web.templating import TEMPLATES_DIR

SHEET = Path(TEMPLATES_DIR).parent / "static" / "app.css"
NARROW = re.compile(
    r"@container filters \(max-width: 440px\)\s*\{\s*"
    r"\.filter-bar--changes \.search\s*\{([^}]*)\}"
)


def test_the_change_search_takes_a_row_of_its_own_on_a_narrow_bar() -> None:
    text = SHEET.read_text(encoding="utf-8")
    assert "container: filters / inline-size" in text
    match = NARROW.search(text)
    assert match is not None, "no narrow rule for the change search"
    assert "flex-basis: 100%" in match.group(1)
    # it applies with or without ::details-content: it sits before that @supports block
    assert text.index(match.group(0)) < text.index("@supports selector(::details-content)")
