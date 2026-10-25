"""THE-1060: the dashboard's stat grid holds the four metric cards and nothing else.

The stylesheet test in test_dashboard.py pins the grid's tracks (four, two, one), so a stray
child of the grid would take a track of its own. This renders the grid of dashboard.html on its
own, for an admin and for a viewer, whose admin-only card is drawn without its link.
"""

import re
from pathlib import Path
from types import SimpleNamespace

from driftsniff.web.templating import make_environment

TEMPLATES = Path(__file__).resolve().parents[2] / "src" / "driftsniff" / "web" / "templates"
CARDS = r'(?:<(a|div) class="card metric".*?</\2>\s*)+'


def _stat_grid(role: str) -> str:
    """The stat grid of dashboard.html, rendered with four stats for a user of the role."""
    page = (TEMPLATES / "dashboard.html").read_text(encoding="utf-8")
    found = re.search(r'<div class="stat-grid">.*?</div>', page, re.DOTALL)
    assert found is not None
    source = '{% from "components/cards.html" import metric_card %}' + found.group(0)
    stats = [
        SimpleNamespace(
            label=f"Stat {number}",
            value=number,
            href=f"/stat/{number}",
            admin_only=number == 3,
            unit="",
            delta="",
            delta_tone="",
            trend="",
            spark=(),
        )
        for number in range(4)
    ]
    template = make_environment().from_string(source)
    return template.render(
        dashboard=SimpleNamespace(stats=stats), shell=SimpleNamespace(user_role=role)
    )


def test_the_stat_grid_holds_only_the_four_metric_cards() -> None:
    for role, links in (("admin", 4), ("viewer", 3)):
        grid = _stat_grid(role)
        found = re.fullmatch(r'\s*<div class="stat-grid">\s*(' + CARDS + r")</div>\s*", grid, re.S)
        assert found is not None, role
        assert found.group(1).count('class="card metric"') == 4, role
        assert grid.count('<a class="card metric"') == links, role
