"""TEMPORARY (THE-592): print the share of non-empty diffs. Fails on purpose."""

from hypothesis import given

from .fixtures import Inventory, diff, inventory_pairs


def test_measure_non_empty_share() -> None:
    total = 0
    non_empty = 0

    @given(pair=inventory_pairs())
    def counted(pair: tuple[Inventory, Inventory]) -> None:
        nonlocal total, non_empty
        total += 1
        non_empty += bool(diff(*pair))

    counted()
    assert False, f"MEASURED non_empty={non_empty} total={total} share={non_empty / total:.4f}"
