"""Hypothesis profiles for the property tests.

``ci`` (the default) is reproducible: derandomised, 500 examples, no example database.
``nightly`` draws a new random seed on every run and tries more examples; it is meant for the
report-only nightly job (see docs/ci-baseline.md, section 10). Select one with the environment
variable ``HYPOTHESIS_PROFILE``.
"""

import os

from hypothesis import HealthCheck, settings

CI_EXAMPLES = 500
NIGHTLY_EXAMPLES = 5_000
PROFILE_VARIABLE = "HYPOTHESIS_PROFILE"

_HEALTH = [HealthCheck.too_slow, HealthCheck.data_too_large]

settings.register_profile(
    "ci",
    max_examples=CI_EXAMPLES,
    derandomize=True,
    deadline=None,
    database=None,
    print_blob=True,
    suppress_health_check=_HEALTH,
)
settings.register_profile(
    "nightly",
    max_examples=NIGHTLY_EXAMPLES,
    derandomize=False,
    deadline=None,
    database=None,
    print_blob=True,
    suppress_health_check=_HEALTH,
)
settings.load_profile(os.environ.get(PROFILE_VARIABLE, "ci"))
