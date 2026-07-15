"""
core.result
===========

A tiny hand-rolled ``Result[T]`` used for *expected*, routine failures -
a tool not being installed, a target being offline, an SSH auth failing.
These are ordinary control flow in a security tool, not programmer errors,
so they should be values a caller inspects, not exceptions a caller has to
remember to catch (plan.md Section 3). Genuine programmer/setup mistakes
still raise from ``core.exceptions``.

The type is deliberately minimal (no dependency): a Result is either
``ok(value)`` or ``err(message)``. Consumers branch on ``is_ok`` and read
``.value`` / ``.error``.
"""

from __future__ import annotations

from typing import Callable, Generic, Optional, TypeVar

T = TypeVar("T")
U = TypeVar("U")


class Result(Generic[T]):
    """Either a success carrying a value, or a failure carrying a message.

    Construct with the classmethods :meth:`ok` and :meth:`err`; never call
    the constructor directly with a half-populated state.
    """

    __slots__ = ("_value", "_error", "_is_ok")

    def __init__(self, *, value: Optional[T], error: Optional[str], is_ok: bool) -> None:
        self._value = value
        self._error = error
        self._is_ok = is_ok

    # -- constructors ------------------------------------------------------
    @classmethod
    def ok(cls, value: T) -> "Result[T]":
        return cls(value=value, error=None, is_ok=True)

    @classmethod
    def err(cls, error: str) -> "Result[T]":
        return cls(value=None, error=error, is_ok=False)

    # -- inspection --------------------------------------------------------
    @property
    def is_ok(self) -> bool:
        return self._is_ok

    @property
    def is_err(self) -> bool:
        return not self._is_ok

    @property
    def value(self) -> T:
        """The success value. Raises if called on an error Result."""
        if not self._is_ok:
            raise ValueError(f"Result.value read on an error Result: {self._error!r}")
        return self._value  # type: ignore[return-value]

    @property
    def error(self) -> str:
        """The failure message. Raises if called on an ok Result."""
        if self._is_ok:
            raise ValueError("Result.error read on an ok Result")
        return self._error  # type: ignore[return-value]

    # -- combinators -------------------------------------------------------
    def map(self, fn: Callable[[T], U]) -> "Result[U]":
        """Transform an ok value; pass an error through untouched."""
        if self._is_ok:
            return Result.ok(fn(self._value))  # type: ignore[arg-type]
        return Result.err(self._error)  # type: ignore[arg-type]

    def unwrap_or(self, default: T) -> T:
        """The value if ok, otherwise ``default`` (never raises)."""
        return self._value if self._is_ok else default  # type: ignore[return-value]

    def __repr__(self) -> str:
        if self._is_ok:
            return f"Result.ok({self._value!r})"
        return f"Result.err({self._error!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Result):
            return NotImplemented
        return (
            self._is_ok == other._is_ok
            and self._value == other._value
            and self._error == other._error
        )
