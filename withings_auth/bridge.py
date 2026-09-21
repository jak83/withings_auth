"""
Withings token bridge - share one Withings authorisation across machines.

Tokens live behind an HTTP endpoint guarded by a shared secret:

    WITHINGS_TOKEN_URL       e.g. https://klaanisodat.fi/api/withings-token
    WITHINGS_BRIDGE_SECRET   sent as "Authorization: Bearer <secret>"

When WITHINGS_TOKEN_URL is unset every function here is a no-op and the caller
falls back to a local token file.

Deliberately the same shape as garmin_auth.bridge - the two endpoints share a
service and an auth scheme. The duplication is small and keeps each package
installable on its own; factor it out if a third service ever appears.
"""
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 10


def bridge_url():
    """Return the configured bridge URL, or None when the bridge is disabled."""
    return os.environ.get("WITHINGS_TOKEN_URL")


def _bridge_headers():
    """Return auth headers for the bridge, or None when no secret is set."""
    secret = os.environ.get("WITHINGS_BRIDGE_SECRET")
    return {"Authorization": f"Bearer {secret}"} if secret else None


def is_configured():
    """True when both the URL and the secret are present."""
    return bool(bridge_url()) and bool(_bridge_headers())


def _require_config():
    """
    Validate bridge configuration.

    Returns:
        tuple: (url, headers) when usable, (None, None) when the bridge is off.
    """
    url = bridge_url()
    if not url:
        return None, None
    headers = _bridge_headers()
    if not headers:
        logger.warning("WITHINGS_TOKEN_URL is set but WITHINGS_BRIDGE_SECRET is "
                       "missing; ignoring the bridge and using local tokens.")
        return None, None
    return url, headers


def fetch_tokens(token_dir=None) -> dict:
    """
    Fetch tokens from the bridge, and mirror them locally when a dir is given.

    Args:
        token_dir: optional directory to also write tokens.json into, so a
            bridge outage later still has something to fall back on.

    Returns:
        dict: the tokens, or {} when the bridge is disabled or unreachable.
    """
    url, headers = _require_config()
    if not url:
        return {}

    import requests

    try:
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 404:
            logger.info("No Withings tokens on the bridge yet.")
            return {}
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as e:
        logger.warning(f"Could not fetch Withings tokens from the bridge: {e}")
        return {}

    if not isinstance(tokens, dict) or not tokens.get("access_token"):
        logger.warning("Bridge returned no usable Withings tokens.")
        return {}

    if token_dir:
        try:
            store = Path(token_dir)
            store.mkdir(parents=True, exist_ok=True)
            token_file = store / "tokens.json"
            token_file.write_text(json.dumps(tokens, indent=2))
            restrict(token_file)
        except OSError as e:
            logger.warning(f"Could not cache Withings tokens locally: {e}")

    logger.debug("Loaded Withings tokens from the bridge.")
    return tokens


def push_tokens(tokens: dict) -> bool:
    """
    Publish tokens to the bridge so the other consumers see this rotation.

    Returns:
        bool: True when the bridge accepted them.
    """
    url, headers = _require_config()
    if not url:
        return False

    import requests

    if not tokens.get("access_token") or not tokens.get("refresh_token"):
        logger.warning("Withings tokens look incomplete; not publishing.")
        return False

    try:
        resp = requests.put(url, json=tokens, headers=headers,
                            timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        logger.warning(f"Could not publish Withings tokens to the bridge: {e}")
        return False

    logger.info("Published Withings tokens to the bridge.")
    return True


def restrict(path):
    """
    Make a token file owner-only where the OS supports it.

    Ignored on Windows, where chmod cannot express this.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
