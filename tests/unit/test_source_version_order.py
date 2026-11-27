"""The Sources list sorted by Version compares the numbers of each version, not its text."""

from driftsniff.web.source_pages import version_order


def test_versions_sort_by_their_numbers_and_the_rest_goes_last() -> None:
    reported = [
        "12.2.1",
        "2.21.4",
        "2.4.0p2.cre",
        "2026.11.0",
        "25.10.1",
        "3.5.0",
        "5.1.4",
        "7.0.5",
        "7.2.105",
        "8.3.2",
        "Contoso BMC 2.14.0 (Redfish 1.17.0)",
        None,
        "",
    ]
    ordered = sorted(reported, key=version_order)
    assert ordered[:10] == [
        "2.4.0p2.cre",
        "2.21.4",
        "3.5.0",
        "5.1.4",
        "7.0.5",
        "7.2.105",
        "8.3.2",
        "12.2.1",
        "25.10.1",
        "2026.11.0",
    ]
    assert ordered[10] == "Contoso BMC 2.14.0 (Redfish 1.17.0)"
    assert set(ordered[11:]) == {None, ""}
