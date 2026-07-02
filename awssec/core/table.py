"""A small generic matrix/table a module can contribute to the report.

Some checks are clearer as a grid than as a list of findings — e.g. GuardDuty
feature coverage across many regions. A module builds a :class:`Table`
(columns + labelled rows of short status tokens); the reporter knows how to
render it on the console and embed it in JSON. The data itself stays generic
so the core needs no per-service knowledge.

Cell values are short tokens the reporter colors by convention (see
``report._TOKEN_COLOR``): e.g. ``ON`` (green), ``OFF`` (red), ``SUSPENDED``
(yellow), ``ERR`` (magenta), ``-`` (not applicable, dim).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TableRow:
    """One row: a human label, a machine-friendly key, and one cell per column.

    ``key`` identifies the row for downstream tooling -- a check_id when
    rows are checks (GuardDuty), a bucket name when rows are resources (S3).
    """

    label: str  # e.g. "S3 Protection" or a bucket name
    key: str  # e.g. "guardduty_s3_protection" or "my-bucket"
    cells: list[str]  # one token per column, in column order


@dataclass
class Table:
    """A titled grid. ``service`` ties it back to the module that produced it."""

    title: str
    service: str
    corner: str  # top-left header cell (label for the row dimension)
    columns: list[str]  # column headers (e.g. region names)
    rows: list[TableRow]

    def to_dict(self) -> dict:
        """JSON form: each row maps column header -> cell token."""
        return {
            "title": self.title,
            "service": self.service,
            "dimension": self.corner,
            "columns": self.columns,
            "rows": [
                {
                    "label": r.label,
                    "key": r.key,
                    "cells": dict(zip(self.columns, r.cells)),
                }
                for r in self.rows
            ],
        }
