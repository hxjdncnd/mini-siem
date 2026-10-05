"""Detection rules: loaded from YAML, validated up front so a typo fails at startup, not at 3am.

A rule has a ``match`` block (which events it cares about), a ``group_by`` (who the alert is
about) and a ``type`` that says how matching events turn into an alert:

``match``     every matching event is evidence (signatures: SQL injection in a URL, a scanner's user agent)
``threshold`` at least N matching events inside a sliding window (brute force)
``distinct``  at least N *different values* of one field inside a sliding window (port scan, password spray)
``sequence``  at least N matching events, then a ``then`` event within a time limit (brute force that worked)
"""

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote_plus

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, model_validator
from sqlalchemy import ColumnElement

from app.enums import Severity
from app.models import EVENT_FIELDS, LogEvent

_OPERATORS = {"regex", "in", "not_in", "gte", "lte"}


class RuleError(ValueError):
    pass


class Condition:
    """One test against one event field. A missing (NULL) field never matches."""

    def __init__(self, field: str, op: str, value: Any):
        if field not in EVENT_FIELDS:
            raise ValueError(f"unknown event field '{field}' (known: {sorted(EVENT_FIELDS)})")
        self.field, self.op, self.value = field, op, value
        self._test = self._compile()

    def _compile(self) -> Callable[[Any], bool]:
        op, value = self.op, self.value
        if op == "eq":
            return lambda v: v == value
        if op in ("in", "not_in"):
            if not isinstance(value, list) or not value:
                raise ValueError(f"'{op}' on '{self.field}' needs a non-empty list")
            options = set(value)
            return (lambda v: v in options) if op == "in" else (lambda v: v not in options)
        if op in ("gte", "lte"):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"'{op}' on '{self.field}' needs a number")
            return (lambda v: v >= value) if op == "gte" else (lambda v: v <= value)
        if op == "regex":
            try:
                pattern = re.compile(str(value), re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"bad regex on '{self.field}': {e}") from None
            # Attackers URL-encode payloads (%27 for '), so test the decoded form too.
            return lambda v: bool(pattern.search(str(v)) or pattern.search(unquote_plus(str(v))))
        raise ValueError(f"unknown operator '{op}' on '{self.field}' (known: {sorted(_OPERATORS)})")

    def test(self, event: LogEvent) -> bool:
        value = getattr(event, self.field)
        return value is not None and self._test(value)

    def sql(self) -> ColumnElement[bool] | None:
        """The same test as SQL where that is possible, so the database can narrow candidates first."""
        column = getattr(LogEvent, self.field)
        match self.op:
            case "eq":
                return column == self.value
            case "in":
                return column.in_(self.value)
            case "gte":
                return column >= self.value
            case "lte":
                return column <= self.value
        return None  # regex / not_in are applied in Python


def compile_conditions(block: dict[str, Any]) -> list[Condition]:
    """``{action: X}`` is equality, ``{action: [X, Y]}`` is any-of, ``{field: {op: value}}`` is explicit."""
    conditions = []
    for field, spec in block.items():
        if isinstance(spec, dict):
            if not spec:
                raise ValueError(f"empty condition on '{field}'")
            conditions += [Condition(field, op, value) for op, value in spec.items()]
        elif isinstance(spec, list):
            conditions.append(Condition(field, "in", spec))
        else:
            conditions.append(Condition(field, "eq", spec))
    return conditions


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=64)
    name: str
    description: str = ""
    severity: Severity
    type: Literal["match", "threshold", "distinct", "sequence"]
    match: dict[str, Any] = Field(min_length=1)
    group_by: list[str] = Field(min_length=1)
    window_seconds: int | None = Field(default=None, gt=0)
    threshold: int | None = Field(default=None, gt=0)
    distinct_field: str | None = None
    then: dict[str, Any] | None = None
    within_seconds: int | None = Field(default=None, gt=0)
    # Further hits for the same entity inside this gap extend the existing alert instead of opening a new one.
    suppress_seconds: int | None = Field(default=None, gt=0)
    summary: str | None = None
    mitre: str | None = None
    enabled: bool = True

    _conditions: list[Condition] = PrivateAttr(default_factory=list)
    _then_conditions: list[Condition] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> "Rule":
        unknown = [f for f in self.group_by if f not in EVENT_FIELDS]
        if unknown:
            raise ValueError(f"group_by has unknown event fields {unknown}")

        def need(*names: str) -> None:
            missing = [n for n in names if getattr(self, n) is None]
            if missing:
                raise ValueError(f"a '{self.type}' rule needs {missing}")

        def forbid(*names: str) -> None:
            present = [n for n in names if getattr(self, n) is not None]
            if present:
                raise ValueError(f"a '{self.type}' rule does not use {present}")

        match self.type:
            case "match":
                forbid("window_seconds", "threshold", "distinct_field", "then", "within_seconds")
            case "threshold":
                need("window_seconds", "threshold")
                forbid("distinct_field", "then", "within_seconds")
            case "distinct":
                need("window_seconds", "threshold", "distinct_field")
                forbid("then", "within_seconds")
                if self.distinct_field not in EVENT_FIELDS:
                    raise ValueError(f"distinct_field '{self.distinct_field}' is not an event field")
            case "sequence":
                need("threshold", "then", "within_seconds")
                forbid("window_seconds", "distinct_field")

        self._conditions = compile_conditions(self.match)
        self._then_conditions = compile_conditions(self.then) if self.then else []
        return self

    # --- used by the engine ---

    def matches(self, event: LogEvent) -> bool:
        return all(c.test(event) for c in self._conditions)

    def then_matches(self, event: LogEvent) -> bool:
        return bool(self._then_conditions) and all(c.test(event) for c in self._then_conditions)

    def sql_prefilter(self) -> list[ColumnElement[bool]]:
        return [clause for c in self._conditions if (clause := c.sql()) is not None]

    def key_of(self, event: LogEvent) -> tuple | None:
        """The entity this event counts toward, or None if the event lacks a group_by field."""
        key = tuple(getattr(event, f) for f in self.group_by)
        return None if any(v is None for v in key) else key

    @property
    def window_ms(self) -> int:
        return (self.window_seconds or 0) * 1000

    @property
    def within_ms(self) -> int:
        return (self.within_seconds or 0) * 1000

    @property
    def suppress_ms(self) -> int:
        return (self.suppress_seconds or self.window_seconds or self.within_seconds or 600) * 1000


def load_rules(directory: Path) -> list[Rule]:
    """Load every .yml/.yaml file in a directory. A file holds one rule or a list of rules."""
    if not directory.is_dir():
        raise RuleError(f"Rules directory not found: {directory}")
    rules: dict[str, Rule] = {}
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleError(f"{path.name}: invalid YAML: {e}") from None
        if loaded is None:
            continue
        for raw in loaded if isinstance(loaded, list) else [loaded]:
            if not isinstance(raw, dict):
                raise RuleError(f"{path.name}: a rule must be a mapping, got {type(raw).__name__}")
            try:
                rule = Rule.model_validate(raw)
            except ValidationError as e:
                problems = "; ".join(f"{'.'.join(map(str, err['loc'])) or 'rule'}: {err['msg']}" for err in e.errors())
                raise RuleError(f"{path.name}: rule '{raw.get('id', '?')}': {problems}") from None
            if rule.id in rules:
                raise RuleError(f"{path.name}: duplicate rule id '{rule.id}'")
            rules[rule.id] = rule
    return list(rules.values())
