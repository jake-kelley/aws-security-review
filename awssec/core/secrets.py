"""Heuristic for spotting inline credentials by variable/field name.

Shared by modules that inspect plaintext key/value configuration where a
secret ought to live in Secrets Manager or SSM Parameter Store instead --
Lambda environment variables and ECS container environment. Only the
*names* are ever examined; callers never read or report the values.

The heuristic is deliberately conservative: a name must contain a
credential-ish fragment (``PASSWORD``, ``SECRET``, ``TOKEN``, ...) *and*
not end in a word that marks it as a mere pointer to a secret (``*_ARN``,
``*_NAME``, ``*_URL``, ...), which is exactly the recommended pattern.
False positives/negatives are possible; this flags names worth a look.
"""

from __future__ import annotations

import re

# Name fragments that suggest a credential is stored in the value.
_SECRET_HINTS = (
    "SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL",
)

# ...unless the name's last word says it's a *pointer* to a secret (an ARN or
# parameter name), which is exactly the recommended pattern.
_POINTER_WORDS = {
    "ARN", "NAME", "PATH", "URL", "URI", "ENDPOINT", "REGION", "PREFIX",
    "ALIAS", "ID", "TABLE", "BUCKET", "TOPIC", "QUEUE", "ROLE",
}


def looks_like_secret_name(name: str) -> bool:
    """Heuristic: does this variable/field *name* suggest an inline credential?"""
    upper = name.upper()
    if not any(hint in upper for hint in _SECRET_HINTS):
        return False
    words = [w for w in re.split(r"[^A-Z0-9]+", upper) if w]
    return not (words and words[-1] in _POINTER_WORDS)
