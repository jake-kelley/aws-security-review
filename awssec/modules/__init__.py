"""Service modules. Each exposes ``SERVICE`` and ``run(ctx) -> ScanResult``.

To add a service later (EC2, Lambda, ...), create a module with that
interface and register it in ``MODULES`` below. The CLI does the rest.
"""

from __future__ import annotations

from . import guardduty, iam, s3

# name -> module. Order here is the default scan order.
MODULES = {
    iam.SERVICE: iam,
    s3.SERVICE: s3,
    guardduty.SERVICE: guardduty,
}
