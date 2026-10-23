"""The planned routes of the change pages (P10-T6): their rows and the role rules they follow.

The frontend slice adds the routes. Until it does, ``PLANNED_ROUTES`` records who may call each
one, and these tests keep the rows consistent with the route table and with the roles of the plan
(a viewer reads; an operator acknowledges, writes notes and mutes).
"""

import pytest

from .appkit import Kit
from .routekit import PLANNED_ROUTES, ROUTE_TABLE, Access, real_routes

ROLE_FOR_READING = Access.VIEWER
ROLES_FOR_WRITING = frozenset({Access.OPERATOR, Access.ADMIN})


def test_a_planned_route_that_exists_is_in_the_route_table(kit: Kit) -> None:
    real = real_routes(kit.app)
    for key, access in PLANNED_ROUTES.items():
        if key in real:
            assert ROUTE_TABLE.get(key) == access, f"{key} is a route; move its row to ROUTE_TABLE"


def test_no_row_is_planned_and_listed_with_another_access() -> None:
    for key, access in PLANNED_ROUTES.items():
        if key in ROUTE_TABLE:
            assert ROUTE_TABLE[key] == access, f"{key} is listed twice with different access"


@pytest.mark.parametrize(("method", "path"), sorted(PLANNED_ROUTES))
def test_a_planned_route_follows_the_role_rules(method: str, path: str) -> None:
    access = PLANNED_ROUTES[(method, path)]
    if method == "GET":
        assert access is ROLE_FOR_READING
    else:
        assert method == "POST"
        assert access in ROLES_FOR_WRITING


def test_every_page_action_of_the_plan_has_a_planned_route() -> None:
    wanted = {
        ("GET", "/changes"),
        ("GET", "/changes/{event_id}"),
        ("POST", "/changes/{event_id}/acknowledge"),
        ("POST", "/changes/{event_id}/notes"),
        ("POST", "/changes/items/{item_id}/mute"),
    }
    assert wanted <= set(PLANNED_ROUTES)
