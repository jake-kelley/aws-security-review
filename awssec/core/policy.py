"""Helpers for reading IAM/resource policy JSON documents.

Policy documents are awkward to inspect directly because almost every
field can be either a single string or a list, and actions/resources use
``*`` glob wildcards. These helpers normalise that so the checks stay
readable.
"""

from __future__ import annotations

import fnmatch
from typing import Iterable


def as_list(value) -> list:
    """Normalise a policy field that may be a string, list, or missing."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document) -> list[dict]:
    """Return the statement list of a policy document.

    Accepts the parsed document (a dict). ``Statement`` itself may be a
    single dict or a list of dicts.
    """
    if not isinstance(document, dict):
        return []
    return [s for s in as_list(document.get("Statement")) if isinstance(s, dict)]


def allow_statements(document) -> Iterable[dict]:
    """Yield only the ``Effect: Allow`` statements."""
    for stmt in statements(document):
        if stmt.get("Effect") == "Allow":
            yield stmt


def action_matches(policy_action: str, target_action: str) -> bool:
    """True if an action string from a policy would grant ``target_action``.

    Honours IAM glob wildcards, e.g. ``guardduty:*`` or ``guardduty:Delete*``
    or a bare ``*`` all match ``guardduty:DeleteDetector``. Matching is
    case-insensitive, as IAM action matching is.
    """
    return fnmatch.fnmatchcase(target_action.lower(), policy_action.lower())


def grants_any(statement: dict, target_actions: Iterable[str]) -> list[str]:
    """Return the subset of ``target_actions`` this Allow statement grants.

    Only considers the ``Action`` element (not ``NotAction`` — see module
    note). Empty list means the statement grants none of them.
    """
    policy_actions = [a for a in as_list(statement.get("Action")) if isinstance(a, str)]
    matched = []
    for target in target_actions:
        if any(action_matches(pa, target) for pa in policy_actions):
            matched.append(target)
    return matched


def has_wildcard_action(statement: dict) -> bool:
    """True if the statement's Action is a bare ``*`` (full admin verbs)."""
    return any(a == "*" for a in as_list(statement.get("Action")) if isinstance(a, str))


def has_wildcard_resource(statement: dict) -> bool:
    """True if the statement's Resource is a bare ``*`` (all resources)."""
    return any(r == "*" for r in as_list(statement.get("Resource")) if isinstance(r, str))


def principal_is_wildcard(statement: dict) -> bool:
    """True if a trust/resource policy statement allows ``*`` principals.

    Matches both ``"Principal": "*"`` and ``"Principal": {"AWS": "*"}``.
    """
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if any(v == "*" for v in as_list(value)):
                return True
    return False
