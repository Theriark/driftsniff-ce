"""The routes of the change pages (P10-T6): the plan's rows against the real routes.

Slice A (the services) planned the routes and their roles in ``PLANNED_ROUTES``; slice B (the
pages) added them. These tests keep the plan and the application in step: every planned row is
a route, it is listed in the route table with the planned access, and the access follows the
roles of the plan (a viewer reads; an operator acknowledges, writes notes and mutes). The route
table test then calls each route as every kind of caller.
"""

import pytest

from .appkit import Kit
from .routekit import PLANNED_ROUTES, ROUTE_TABLE, Access, real_routes

ROLE_FOR_READING = Access.VIEWER
ROLES_FOR_WRITING = frozenset({Access.OPERATOR, Access.ADMIN})


def test_every_planned_route_exists_and_is_in_the_route_table(kit: Kit) -> None:
    real = real_routes(kit.app)
    for key, access in PLANNED_ROUTES.items():
        assert key in real, f"{key} is planned but not a route"
        assert ROUTE_TABLE.get(key) == access, f"{key} is listed with another access"


def test_no_row_is_planned_and_listed_with_another_access() -> None:
    for key, access in PLANNED_ROUTES.items():
        assert ROUTE_TABLE[key] == access, f"{key} is listed twice with different access"


@pytest.mark.parametrize(("method", "path"), sorted(PLANNED_ROUTES))
def test_a_planned_route_follows_the_role_rules(method: str, path: str) -> None:
    access = PLANNED_ROUTES[(method, path)]
    if method == "GET":
        assert access is ROLE_FOR_READING
    else:
        assert method == "POST"
        assert access in ROLES_FOR_WRITING


def test_every_page_action_of_the_plan_has_a_route() -> None:
    wanted = {
        ("GET", "/changes"),
        ("GET", "/changes/{event_id}"),
        ("POST", "/changes/{event_id}/acknowledge"),
        ("POST", "/changes/{event_id}/notes"),
        ("POST", "/changes/items/{item_id}/mute"),
        ("POST", "/mutes/{mute_id}/remove"),
    }
    assert wanted <= set(PLANNED_ROUTES)
    assert wanted <= set(ROUTE_TABLE)
