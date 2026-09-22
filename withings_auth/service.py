"""
Token service mode - fetch a short-lived access token from the server.

The server owns the Withings refresh token and is the only thing that rotates
it, so a client in this mode holds nothing long-lived and never refreshes.
That removes the rotation race rather than merely coping with it.

Configure with two variables, shared with garmin_auth:

    TOKEN_SERVICE_URL   e.g. https://example.com/auth
    TOKEN_SERVICE_KEY   this machine's API key

When either is missing this mode is off and the caller falls back to managing
its own tokens.
"""
import logging
import os

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15


def service_url():
    """Base URL of the token service, or None when not configured."""
    url = os.environ.get("TOKEN_SERVICE_URL")
    return url.rstrip("/") if url else None


def api_key():
    """This machine's API key, or None."""
    return os.environ.get("TOKEN_SERVICE_KEY")


def is_configured():
    """True when both the URL and this machine's key are present."""
    return bool(service_url()) and bool(api_key())


def fetch_access_token() -> dict:
    """
    Fetch a current Withings access token from the service.

    Returns:
        dict: {"access_token": str, "expires_at": float|None, "userid": ...}

    Raises:
        RuntimeError: when the service is unreachable, rejects the key, or has
        nothing usable.
    """
    base = service_url()
    if not base:
        raise RuntimeError("TOKEN_SERVICE_URL is not set")
    if not api_key():
        raise RuntimeError("TOKEN_SERVICE_KEY is not set")

    import requests

    try:
        resp = requests.get(
            f"{base}/withings/access-token",
            headers={"Authorization": f"Bearer {api_key()}"},
            timeout=HTTP_TIMEOUT,
        )
    except Exception as e:
        raise RuntimeError(f"Token service unreachable: {e}")

    if resp.status_code == 401:
        raise RuntimeError("Token service rejected this machine's API key")
    if resp.status_code == 404:
        raise RuntimeError("Token service has no Withings token stored yet")
    if resp.status_code == 503:
        # Only the server can refresh, so say so plainly.
        raise RuntimeError("Token service reports the Withings token expired")
    if resp.status_code != 200:
        raise RuntimeError(f"Token service returned {resp.status_code}")

    payload = resp.json()
    if not payload.get("access_token"):
        raise RuntimeError("Token service returned no Withings access token")

    logger.info("Fetched a Withings access token from the token service.")
    return payload
