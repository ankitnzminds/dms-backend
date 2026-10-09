"""The constrained expression language: it must evaluate simple conditions and refuse everything else."""

from __future__ import annotations

import pytest

from app.modules.automations import expr

NAMES = frozenset({"file.name", "file.size_bytes", "file.extension", "file.path", "vars.big"})
CTX = {
    "file": {
        "name": "Q3 Report.PDF",
        "size_bytes": 2048,
        "extension": "pdf",
        "path": "/Finance/Q3 Report.PDF",
    },
    "vars": {"big": True},
}


def ev(src: str) -> object:
    return expr.evaluate(src, CTX, NAMES)


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("file.size_bytes > 1000", True),
        ("file.size_bytes <= 1000", False),
        ("file.extension == 'pdf'", True),
        ("file.extension in ['pdf', 'docx']", True),
        ("file.extension not in ['png']", True),
        ("file.name contains 'report'", True),  # case-insensitive
        ("file.path startswith '/finance'", True),
        ("file.name endswith '.pdf'", True),
        ("file.name matches '^q\\d report'", True),
        ("file.extension == 'pdf' and file.size_bytes > 100 or false", True),
        ("not (file.size_bytes > 100)", False),
        ("vars.big == true", True),
        ("(file.size_bytes > 1 and file.size_bytes < 3000) and file.extension != 'txt'", True),
    ],
)
def test_evaluates(src: str, expected: bool) -> None:
    assert ev(src) is expected


@pytest.mark.parametrize(
    "src",
    [
        "__import__('os').system('x')",  # no calls
        "file.name.upper() == 'X'",  # no method calls / attribute access beyond names
        "open('/etc/passwd')",
        "file.owner == 1",  # unknown variable is an error, not null
        "file.size_bytes >",
        "(file.size_bytes > 1",
        "file.name matches '(a+)+$'",  # nested quantifier
        "file.name matches '" + "a" * 101 + "'",
        "x = 1",
        "",
        "1; 2",
        "file.size_bytes > 1 " + "and file.size_bytes > 1 " * 40,  # too long
    ],
)
def test_rejects(src: str) -> None:
    with pytest.raises(expr.ExprError):
        ev(src)


def test_comparisons_never_raise_on_mismatched_types() -> None:
    assert ev("file.name > 5") is False
    assert ev("file.size_bytes contains 'x'") is False
    assert (
        expr.evaluate("file.name == null", {"file": {"name": None}}, frozenset({"file.name"}))
        is True
    )


def test_names_in_lists_leaves() -> None:
    assert expr.names_in({"a": {"b": 1, "c": {"d": 2}}, "e": 3}) == frozenset({"a.b", "a.c.d", "e"})
