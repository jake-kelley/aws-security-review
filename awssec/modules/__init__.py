"""Service modules. Each exposes ``SERVICE`` and ``run(ctx) -> ScanResult``.

To add a service later (EC2, Lambda, ...), create a module with that
interface and register it in ``MODULES`` below. The CLI does the rest.
"""

from __future__ import annotations

# lambda_ because "lambda" is a Python keyword; its SERVICE name is "lambda".
from . import ec2, ecs, eks, guardduty, iam, lambda_, s3

# name -> module. Order here is the default scan order.
MODULES = {
    iam.SERVICE: iam,
    s3.SERVICE: s3,
    ec2.SERVICE: ec2,
    lambda_.SERVICE: lambda_,
    ecs.SERVICE: ecs,
    eks.SERVICE: eks,
    guardduty.SERVICE: guardduty,
}
