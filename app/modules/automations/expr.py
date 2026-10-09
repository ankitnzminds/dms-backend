"""A deliberately tiny, constrained expression language for automation conditions.

Grammar (no eval, no attribute calls, no network, no I/O):

    expr    := or
    or      := and ("or" and)*
    and     := not ("and" not)*
    not     := "not" not | cmp
    cmp     := atom (("==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not in" | "contains"
                      | "startswith" | "endswith" | "matches") atom)?
    atom    := "(" expr ")" | literal | list | name
    literal := "string" | 'string' | number | true | false | null
    name    := identifier ("." identifier)*      -- looked up in an allowlisted context only

Unknown names are a *validation error*, not silently null, so a typo is caught at save time.
``matches`` takes a regular expression with tight limits (pattern/subject length, no nested
quantifiers) to avoid catastrophic backtracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

MAX_EXPR_LEN = 500
MAX_REGEX_LEN = 100
MAX_SUBJECT_LEN = 1000
MAX_DEPTH = 20


class ExprError(ValueError):
    """Invalid expression (syntax, unknown name, bad operand). Message is safe to show."""


_TOKEN = re.compile(
    r"""\s*(?:
        (?P<num>-?\d+(?:\.\d+)?)
      | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
      | (?P<op>==|!=|<=|>=|<|>|\(|\)|\[|\]|,)
      | (?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
    )""",
    re.VERBOSE,
)
_KEYWORDS = {"and", "or", "not", "in", "contains", "startswith", "endswith", "matches"}
_LITERALS = {"true": True, "false": False, "null": None}
_NESTED_QUANT = re.compile(r"(\([^)]*[*+{][^)]*\))\s*[*+{]|[*+]\s*[*+]")


@dataclass(frozen=True)
class Tok:
    kind: str
    value: Any


def _tokenize(src: str) -> list[Tok]:
    if len(src) > MAX_EXPR_LEN:
        raise ExprError(f"Expression is longer than {MAX_EXPR_LEN} characters.")
    pos, out = 0, []
    while pos < len(src):
        if src[pos:].strip() == "":
            break
        m = _TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ExprError(f"Unexpected character near position {pos + 1}.")
        pos = m.end()
        if m.group("num") is not None:
            raw = m.group("num")
            out.append(Tok("lit", float(raw) if "." in raw else int(raw)))
        elif m.group("str") is not None:
            body = m.group("str")[1:-1]
            # only quote escapes are removed, so regex escapes such as \d reach `matches` intact
            out.append(Tok("lit", re.sub(r"\\(['\"])", r"\1", body)))
        elif m.group("op") is not None:
            out.append(Tok("op", m.group("op")))
        else:
            word = m.group("name")
            if word in _LITERALS:
                out.append(Tok("lit", _LITERALS[word]))
            elif word in _KEYWORDS:
                out.append(Tok("kw", word))
            else:
                out.append(Tok("name", word))
    return out


# ---- AST as nested tuples: ("lit", v) ("name", n) ("list", [..]) ("not", x) ("bin", op, a, b)
class _Parser:
    def __init__(self, toks: list[Tok], names: frozenset[str]) -> None:
        self.t, self.i, self.names, self.depth = toks, 0, names, 0

    def peek(self) -> Tok | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> Tok:
        tok = self.peek()
        if tok is None:
            raise ExprError("The expression ended unexpectedly.")
        self.i += 1
        return tok

    def kw(self, word: str) -> bool:
        tok = self.peek()
        if tok and tok.kind == "kw" and tok.value == word:
            self.i += 1
            return True
        return False

    def parse(self) -> tuple[Any, ...]:
        if not self.t:
            raise ExprError("The expression is empty.")
        node = self.or_()
        if self.peek() is not None:
            raise ExprError(f"Unexpected '{self.peek().value}'.")  # type: ignore[union-attr]
        return node

    def or_(self) -> tuple[Any, ...]:
        node = self.and_()
        while self.kw("or"):
            node = ("bin", "or", node, self.and_())
        return node

    def and_(self) -> tuple[Any, ...]:
        node = self.not_()
        while self.kw("and"):
            node = ("bin", "and", node, self.not_())
        return node

    def not_(self) -> tuple[Any, ...]:
        if self.kw("not"):
            return ("not", self.not_())
        return self.cmp()

    def cmp(self) -> tuple[Any, ...]:
        left = self.atom()
        tok = self.peek()
        if tok is None:
            return left
        op: str | None = None
        if (
            tok.kind == "op"
            and tok.value in ("==", "!=", "<", "<=", ">", ">=")
            or tok.kind == "kw"
            and tok.value in ("in", "contains", "startswith", "endswith", "matches")
        ):
            op = self.take().value
        elif tok.kind == "kw" and tok.value == "not":
            nxt = self.t[self.i + 1] if self.i + 1 < len(self.t) else None
            if nxt and nxt.kind == "kw" and nxt.value == "in":
                self.i += 2
                op = "not in"
        if op is None:
            return left
        right = self.atom()
        if op == "matches":
            self._check_regex(right)
        return ("bin", op, left, right)

    @staticmethod
    def _check_regex(node: tuple[Any, ...]) -> None:
        if node[0] != "lit" or not isinstance(node[1], str):
            raise ExprError("'matches' needs a quoted regular expression.")
        pattern = node[1]
        if len(pattern) > MAX_REGEX_LEN:
            raise ExprError(f"Regular expression is longer than {MAX_REGEX_LEN} characters.")
        if _NESTED_QUANT.search(pattern):
            raise ExprError("Nested quantifiers are not allowed in regular expressions.")
        try:
            re.compile(pattern)
        except re.error as e:
            raise ExprError(f"Invalid regular expression: {e}") from None

    def atom(self) -> tuple[Any, ...]:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExprError("The expression is nested too deeply.")
        try:
            tok = self.take()
            if tok.kind == "lit":
                return ("lit", tok.value)
            if tok.kind == "name":
                if tok.value not in self.names:
                    raise ExprError(
                        f"Unknown variable '{tok.value}'. Available: {', '.join(sorted(self.names))}."
                    )
                return ("name", tok.value)
            if tok.kind == "op" and tok.value == "(":
                node = self.or_()
                close = self.take()
                if close.value != ")":
                    raise ExprError("Missing ')'.")
                return node
            if tok.kind == "op" and tok.value == "[":
                items: list[Any] = []
                if self.peek() and self.peek().value == "]":  # type: ignore[union-attr]
                    self.take()
                    return ("list", items)
                while True:
                    items.append(self.atom())
                    sep = self.take()
                    if sep.value == "]":
                        return ("list", items)
                    if sep.value != ",":
                        raise ExprError("Expected ',' or ']' in list.")
            raise ExprError(f"Unexpected '{tok.value}'.")
        finally:
            self.depth -= 1


def parse(src: str, names: frozenset[str]) -> tuple[Any, ...]:
    """Parse and validate against the allowed variable names. Raises ExprError."""
    return _Parser(_tokenize(src), names).parse()


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _eval(node: tuple[Any, ...], ctx: dict[str, Any]) -> Any:
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "name":
        value: Any = ctx
        for part in node[1].split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return value
    if kind == "list":
        return [_eval(n, ctx) for n in node[1]]
    if kind == "not":
        return not _eval(node[1], ctx)
    _, op, a, b = node
    if op == "and":
        return bool(_eval(a, ctx)) and bool(_eval(b, ctx))
    if op == "or":
        return bool(_eval(a, ctx)) or bool(_eval(b, ctx))
    left, right = _eval(a, ctx), _eval(b, ctx)
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op in ("<", "<=", ">", ">="):
        if not ((_num(left) and _num(right)) or (isinstance(left, str) and isinstance(right, str))):
            return False
        return {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right}[op]
    if op == "in":
        return left in right if isinstance(right, (list, str)) and left is not None else False
    if op == "not in":
        return left not in right if isinstance(right, (list, str)) and left is not None else True
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if op == "contains":
        return right.lower() in left.lower()
    if op == "startswith":
        return left.lower().startswith(right.lower())
    if op == "endswith":
        return left.lower().endswith(right.lower())
    if op == "matches":
        return re.search(right, left[:MAX_SUBJECT_LEN], re.IGNORECASE) is not None
    raise ExprError(f"Unsupported operator '{op}'.")  # pragma: no cover


def evaluate(src: str, ctx: dict[str, Any], names: frozenset[str]) -> Any:
    return _eval(parse(src, names), ctx)


def names_in(ctx: dict[str, Any], prefix: str = "") -> frozenset[str]:
    """Dotted names available for a context dict (used to build the allowlist)."""
    out: set[str] = set()
    for k, v in ctx.items():
        full = f"{prefix}{k}"
        if isinstance(v, dict):
            out |= names_in(v, full + ".")
        else:
            out.add(full)
    return frozenset(out)
