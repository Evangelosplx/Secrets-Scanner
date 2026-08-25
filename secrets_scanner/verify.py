"""Opt-in live verification of discovered credentials.

This is the ONLY part of the tool that makes an outbound network request, and
it sends the discovered credential to its provider's API to check whether it is
still active. It runs only when the user passes ``--live-verify`` and only for
secret types we know how to check. Uses the standard library ``urllib`` so it
adds no dependencies, and every failure degrades to ``UNKNOWN`` rather than
raising.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from .models import LiveStatus
from .patterns import GITHUB_TOKEN

DEFAULT_TIMEOUT = 6.0
_USER_AGENT = "secrets-scanner/live-verify"


def verify_github_token(token: str, timeout: float = DEFAULT_TIMEOUT) -> LiveStatus:
    """Check a GitHub token against ``GET /user``.

    * HTTP 200  -> the token authenticates a user: ``ACTIVE``.
    * HTTP 401/403 -> rejected: ``REVOKED``.
    * anything else / network error -> ``UNKNOWN``.
    """
    request = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": _USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return LiveStatus.ACTIVE if response.status == 200 else LiveStatus.UNKNOWN
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            return LiveStatus.REVOKED
        return LiveStatus.UNKNOWN
    except Exception:
        # DNS failure, timeout, TLS error, offline, ... — never crash a scan.
        return LiveStatus.UNKNOWN


# Registry mapping a secret type to its verifier. Add more providers here.
VERIFIERS = {
    GITHUB_TOKEN: verify_github_token,
}


def verify(secret_type: str, value: str, timeout: float = DEFAULT_TIMEOUT) -> LiveStatus:
    """Verify ``value`` if we support ``secret_type``, else ``NOT_CHECKED``."""
    verifier = VERIFIERS.get(secret_type)
    if verifier is None:
        return LiveStatus.NOT_CHECKED
    return verifier(value, timeout=timeout)
