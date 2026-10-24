"""The words and the links of the change pages (P10-T6, frontend slice), on their own.

These are the pure helpers of ``driftsniff.web.change_pages``: the readable field labels, the
one-line item summary, the words of an order move, the marked difference of a before and after
pair, the severity floor of the filter bar, the links that carry the filters, the pager and the
removable chips of the filters in force. The pages themselves are tested through the
application in ``test_web_changes.py``.
"""

from datetime import date
from typing import Any

import pytest

from driftsniff.changes.filters import parse_filters
from driftsniff.changes.views import ChangeFilters, ChangePageView, ItemView, MoveView
from driftsniff.web.change_pages import (
    EXACT_SEVERITIES,
    FilterChip,
    count_words,
    date_words,
    display_value,
    field_label,
    filter_chips,
    filter_query,
    fingerprint_words,
    item_summary,
    kind_label,
    move_text,
    page_summary,
    pager_links,
    panel_filter_count,
    severity_choice,
    severity_params,
    severity_words,
    split_difference,
)


def item(**changes: Any) -> ItemView:
    base: dict[str, Any] = {
        "id": 1,
        "resource": "networks",
        "object_name": "Guest",
        "change_kind": "modified",
        "path": "security",
        "field_class": "config",
        "severity": "high",
        "rule_id": "unifi.wifi.security_downgrade",
        "rationale": "An open network has no encryption.",
        "rationale_recorded": True,
        "before": "wpa2-psk",
        "after": "open",
        "before_fingerprint": None,
        "after_fingerprint": None,
        "secret": False,
        "muted": False,
        "mutable": True,
        "move": None,
        "order_detail": None,
    }
    base.update(changes)
    return ItemView(**base)


# ---- words ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("secureBoot", "Secure boot"),
        ("wlan.security", "Security"),
        ("dns.1", "DNS servers, entry 2"),
        ("", "Whole object"),
        ("some_odd_fieldName", "Some odd field name"),
        ("HA_enabled", "High availability"),
        ("settings/mgmt/ssh-enabled", "Ssh enabled"),
        ("x_passphrase", "Passphrase"),
        ("securityConfiguration.type", "Security type"),
        ("clientIsolationEnabled", "Client isolation"),
    ],
)
def test_a_field_path_reads_as_words(path: str, label: str) -> None:
    assert field_label(path) == label


def test_a_change_kind_reads_as_a_word_and_an_unknown_one_is_spelled_out() -> None:
    assert kind_label("modified") == "Changed"
    assert kind_label("removed") == "Removed"
    assert kind_label("schema_drift") == "New fields"
    assert kind_label("some_new_kind") == "Some new kind"


def test_the_item_summary_names_the_field_and_what_happened() -> None:
    assert item_summary(item()) == "Security changed"
    assert item_summary(item(change_kind="added", path="")) == "Object added"
    assert item_summary(item(change_kind="removed", path="")) == "Object removed"
    assert item_summary(item(secret=True, path="passphrase")) == "Passphrase (secret) changed"
    assert item_summary(item(change_kind="schema_drift", path="a, b")) == (
        "New fields appeared with this version"
    )
    assert item_summary(item(change_kind="order_changed")) == "The order of the list changed"
    moved = item(change_kind="moved", move=MoveView("A", "B", None, None, "C", None))
    assert item_summary(moved) == "A moved from after B to before C."
    assert item_summary(item(change_kind="moved", move=None)) == "Entry moved"


def test_an_order_move_is_written_from_after_to_before_with_the_ends_named() -> None:
    assert move_text(MoveView("Allow IoT", "Block guest", None, None, "Deny IoT", "s")) == (
        "Allow IoT moved from after Block guest to before Deny IoT."
    )
    assert move_text(MoveView(None, None, None, None, None, None)) == (
        "An entry moved from the start to the end."
    )


def test_a_fingerprint_is_grouped_in_fours_and_a_missing_one_is_none() -> None:
    assert fingerprint_words("ab12cd34ef56") == "ab12 cd34 ef56"
    assert fingerprint_words("ab12cd34e") == "ab12 cd34 e"
    assert fingerprint_words(None) == "none"
    assert fingerprint_words("") == "none"


def test_a_stored_json_string_is_shown_without_its_quotes() -> None:
    assert display_value('"Office 5G"') == "Office 5G"
    assert display_value('"say \\"hi\\""') == 'say "hi"'
    assert display_value('""') == ""
    assert display_value("true") == "true"
    assert display_value("10") == "10"
    assert display_value('["a", "b"]') == '["a", "b"]'
    assert display_value("Guest") == "Guest"
    assert display_value('"unterminated') == '"unterminated'
    assert display_value('"a" and "b"') == '"a" and "b"'


def test_the_difference_is_the_middle_that_differs() -> None:
    before, after = split_difference("retention 30 days", "retention 14 days")
    assert (before.prefix, before.changed, before.suffix) == ("retention ", "30", " days")
    assert (after.prefix, after.changed, after.suffix) == ("retention ", "14", " days")
    before, after = split_difference("wpa2-psk", "open")
    assert (before.prefix, before.changed, before.suffix) == ("", "wpa2-psk", "")
    assert after.changed == "open"
    before, after = split_difference("same", "same")
    assert before.changed == "" and before.prefix == "same" and after.suffix == ""
    before, after = split_difference("", "new")
    assert before.changed == "" and after.changed == "new"
    before, after = split_difference("abc", "abcabc")
    assert before.prefix + before.changed + before.suffix == "abc"
    assert after.prefix + after.changed + after.suffix == "abcabc"
    assert after.changed == "abc"


def test_count_words_takes_the_plural_it_is_given() -> None:
    assert count_words(1, "note") == "1 note"
    assert count_words(2, "note") == "2 notes"
    assert count_words(2, "external analysis", "external analyses") == "2 external analyses"
    assert count_words(1200, "change") == "1,200 changes"


# ---- the severity floor -------------------------------------------------------------------


def test_the_severity_select_shows_a_floor_or_the_exact_set() -> None:
    assert severity_choice(parse_filters({"severity": ["critical", "high"]})) == "high"
    assert severity_choice(parse_filters({"severity": ["critical"]})) == "critical"
    assert severity_choice(parse_filters({"severity": ["medium"]})) == EXACT_SEVERITIES
    assert severity_choice(parse_filters({})) == ""


def test_the_floor_of_the_select_becomes_severity_values() -> None:
    assert severity_params({"min": ["high"], "severity": ["low"]})["severity"] == [
        "critical",
        "high",
    ]
    assert "severity" not in severity_params({"min": [""], "severity": ["low"]})
    assert severity_params({"min": ["exact"], "severity": ["low"]})["severity"] == ["low"]
    assert severity_params({"severity": ["low"]}) == {"severity": ["low"]}
    assert "min" not in severity_params({"min": ["nonsense"], "q": ["x"]})


# ---- the links ----------------------------------------------------------------------------


def test_a_filter_link_carries_only_valid_values() -> None:
    assert filter_query(ChangeFilters()) == "/changes"
    filters = ChangeFilters(search="a b", severities=("critical", "high"), page=3, sort="severity")
    assert filter_query(filters) == (
        "/changes?q=a+b&severity=critical&severity=high&sort=severity&page=3"
    )
    assert filter_query(ChangeFilters(page=3), page=None) == "/changes"
    assert filter_query(ChangeFilters(status="open"), muted="1") == "/changes?status=open&muted=1"
    dated = ChangeFilters(created_from=date(2026, 10, 1), created_to=date(2026, 10, 2))
    assert filter_query(dated) == "/changes?from=2026-10-01&to=2026-10-02"


def test_the_pager_shows_a_window_around_the_current_page() -> None:
    view = ChangePageView(rows=(), total=231, page=3, pages=5, page_size=50)
    links = pager_links(ChangeFilters(status="open", page=3), view)
    assert [link.label for link in links] == ["Previous", "1", "2", "3", "4", "5", "Next"]
    assert links[3].current and links[3].href == "/changes?status=open&page=3"
    assert links[0].href == "/changes?status=open&page=2"
    assert links[-1].href == "/changes?status=open&page=4"
    first = pager_links(ChangeFilters(), ChangePageView((), 1000, 1, 20, 50))
    assert [link.label for link in first] == ["1", "2", "3", "20", "Next"]
    assert pager_links(ChangeFilters(), ChangePageView((), 3, 1, 1, 50)) == ()


def test_the_page_summary_counts_what_is_shown() -> None:
    assert page_summary(ChangePageView((), 231, 3, 5, 50)) == "Showing 101 to 150 of 231"
    assert page_summary(ChangePageView((), 0, 1, 1, 50)) == "No changes match"
    assert page_summary(ChangePageView((), 3, 1, 1, 50)) == "3 changes"
    assert page_summary(ChangePageView((), 1, 1, 1, 50)) == "1 change"


def test_every_filter_in_force_is_a_chip_whose_link_drops_only_that_filter() -> None:
    filters = ChangeFilters(
        search="guest",
        source_id=1,
        severities=("critical", "high"),
        status="open",
        resource="networks",
        created_from=date(2026, 10, 1),
        created_to=date(2026, 10, 2),
        sort="oldest",
        page=3,
        include_muted=True,
    )
    chips = filter_chips(filters, {1: "lab"})
    assert [(chip.name, chip.value) for chip in chips] == [
        ("Search", "guest"),
        ("Source", "lab"),
        ("Severity", "High and above"),
        ("Status", "Open"),
        ("Resource", "Networks"),
        ("Detected", "2026-10-01 to 2026-10-02, UTC"),
        ("", "Muted included"),
    ]
    rest = "sort=oldest&muted=1"
    everything = "q=guest&source=1&severity=critical&severity=high&status=open&resource=networks"
    assert chips[0].remove_href.startswith("/changes?source=1&")
    dates = "from=2026-10-01&to=2026-10-02"
    no_status = "q=guest&source=1&severity=critical&severity=high&resource=networks"
    assert chips[3].remove_href == f"/changes?{no_status}&{dates}&{rest}"
    # the two ends of the range go together, the sort stays, and every link is back on page 1
    assert chips[5].remove_href == f"/changes?{everything}&{rest}"
    assert chips[6].remove_href == f"/changes?{everything}&{dates}&sort=oldest"
    assert all("page=" not in chip.remove_href for chip in chips)
    assert filter_chips(ChangeFilters(source_id=9), {}) == (FilterChip("Source", "9", "/changes"),)
    assert filter_chips(ChangeFilters(), {}) == ()


def test_the_severity_and_date_chips_read_as_the_bar_names_them() -> None:
    assert severity_words(ChangeFilters(severities=("critical",))) == "Critical"
    assert severity_words(ChangeFilters(severities=("low",))) == "Low only"
    assert severity_words(ChangeFilters(severities=("low", "high"))) == "High or low"
    assert date_words(ChangeFilters(created_from=date(2026, 10, 1))) == "since 2026-10-01, UTC"
    assert date_words(ChangeFilters(created_to=date(2026, 10, 2))) == "up to 2026-10-02, UTC"
    assert date_words(ChangeFilters()) == ""


def test_the_filters_toggle_counts_the_fields_of_its_panel_only() -> None:
    assert panel_filter_count(ChangeFilters(search="guest", include_muted=True)) == 0
    dated = ChangeFilters(created_from=date(2026, 10, 1), created_to=date(2026, 10, 2))
    assert panel_filter_count(dated) == 1
    every = ChangeFilters(source_id=1, severities=("low",), status="open", resource="networks")
    assert panel_filter_count(every) == 4
