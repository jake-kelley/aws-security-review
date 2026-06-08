"""Service modules. Each exposes ``SERVICE`` and ``run(ctx) -> list[Finding]``.

To add a service later (S3, EC2, Lambda, GuardDuty, ...), create a module
with that interface and register it in ``MODULES`` below. The CLI does the
rest.
"""

from __future__ import annotations

from . import iam

# name -> module. Order here is the default scan order.
MODULES = {
    iam.SERVICE: iam,
}
