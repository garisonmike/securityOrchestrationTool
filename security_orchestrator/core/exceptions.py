"""
core.exceptions
===============

A small, typed exception hierarchy reserved for programmer/setup errors -
the kind of thing that should fail loudly and stop the run, not be folded
into a ``Result`` and quietly worked around (plan.md Section 3 / Section 4).

Routine, expected failures (tool missing at scan time, target offline, auth
rejected) are *not* exceptions here - those are ``core.result.Result``
values. The rule of thumb: if a correct user on a correctly set-up machine
could hit it during a normal scan, it's a ``Result``; if it means the tool
was invoked wrong, it's one of these.
"""


class OrchestratorError(Exception):
    """Base class for every error this package raises deliberately."""


class ConfigError(OrchestratorError):
    """Invalid or self-contradictory scan configuration.

    Raised for bad user/CLI input that cannot produce a meaningful scan -
    an empty target, an unknown module name, an unknown output format.
    """


class ToolNotFoundError(OrchestratorError):
    """A required external tool is absent when the policy is 'fail fast'.

    Note: the default orchestrator policy for a missing tool is to *skip*
    the affected module and record it in the ``Report`` (plan.md Section
    0.1 item 14), so adapters surface a missing binary as ``Result.err``.
    This exception exists for callers that explicitly opt into strict,
    fail-fast behaviour instead.
    """
