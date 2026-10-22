"""Route table (P9-T6): every route, the role it needs, and what happens to everyone else.

``ROUTE_TABLE`` lists every route of the application with the access it requires. Two kinds of
test hold it honest:

* The table and the application must agree. A route that exists but is not in the table fails the
  test (so nobody adds a route without deciding who may use it), and so does a row without a route.
* Every route is called as every kind of caller (nobody, each role with a real session, each kind
  of API token, a made-up token). The callers the access allows must get through; every other
  caller must be refused with 401 or 403. A route that is open below its role fails the test.

Session requests carry a valid Origin and CSRF value, so a 403 means the role check and not the
CSRF check. A session cookie never works on ``/api/v1``, whatever the route (the middleware refuses
it); the table test counts that as a refusal.

Two meta tests prove the checks can fail: a route added without a row is reported, and a route
declared admin-only but left open is reported.
"""

from typing import Annotated

import pytest
from fastapi import Depends

from driftsniff.web.auth import Principal
from driftsniff.web.deps import require_admin

from .appkit import Kit
from .routekit import ROUTE_TABLE, Access, real_routes, violations


def test_every_route_is_in_the_table_and_every_row_is_a_route(kit: Kit) -> None:
    real = real_routes(kit.app)
    listed = set(ROUTE_TABLE)
    assert real - listed == set(), "routes that are missing from ROUTE_TABLE"
    assert listed - real == set(), "rows of ROUTE_TABLE that are not routes"


@pytest.mark.parametrize(("method", "path"), sorted(ROUTE_TABLE))
def test_a_route_lets_through_exactly_the_callers_its_access_allows(
    kit: Kit, method: str, path: str
) -> None:
    assert violations(kit, method, path, ROUTE_TABLE[(method, path)]) == []


def test_a_route_added_without_a_row_is_reported(kit: Kit) -> None:
    @kit.app.get("/api/v1/unlisted")
    def unlisted() -> dict[str, str]:
        return {}

    assert real_routes(kit.app) - set(ROUTE_TABLE) == {("GET", "/api/v1/unlisted")}


def test_a_route_that_is_open_below_its_role_is_reported(kit: Kit) -> None:
    @kit.app.get("/probe/open")
    def open_probe() -> dict[str, str]:
        return {}

    @kit.app.get("/probe/closed")
    def closed_probe(_admin: Annotated[Principal, Depends(require_admin)]) -> dict[str, str]:
        return {}

    problems = violations(kit, "GET", "/probe/open", Access.ADMIN)
    assert any(line.startswith("anonymous:") for line in problems)
    assert any(line.startswith("viewer session:") for line in problems)
    assert violations(kit, "GET", "/probe/closed", Access.ADMIN) == []
