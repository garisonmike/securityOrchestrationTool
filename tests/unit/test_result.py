"""Phase 1 tests for the hand-rolled Result[T]."""

import pytest

from security_orchestrator.core.result import Result


def test_ok_carries_value():
    r = Result.ok(42)
    assert r.is_ok
    assert not r.is_err
    assert r.value == 42


def test_err_carries_message():
    r = Result.err("nmap not found")
    assert r.is_err
    assert not r.is_ok
    assert r.error == "nmap not found"


def test_reading_value_on_err_raises():
    with pytest.raises(ValueError):
        _ = Result.err("boom").value


def test_reading_error_on_ok_raises():
    with pytest.raises(ValueError):
        _ = Result.ok(1).error


def test_map_transforms_ok_and_passes_err_through():
    assert Result.ok(2).map(lambda x: x * 10) == Result.ok(20)
    passed = Result.err("down").map(lambda x: x * 10)
    assert passed.is_err
    assert passed.error == "down"


def test_unwrap_or_never_raises():
    assert Result.ok("v").unwrap_or("default") == "v"
    assert Result.err("e").unwrap_or("default") == "default"


def test_equality_and_repr():
    assert Result.ok(1) == Result.ok(1)
    assert Result.err("x") == Result.err("x")
    assert Result.ok(1) != Result.err("x")
    assert "ok" in repr(Result.ok(1))
    assert "err" in repr(Result.err("x"))
