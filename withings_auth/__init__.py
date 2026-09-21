"""
withings_auth - one shared way to get a valid Withings access token.

    from withings_auth import get_access_token
    token = get_access_token()

Replaces the per-project copies of "load tokens, refresh if expired, save
them again". Withings rotates its refresh token on every use, so the copy
each project keeps locally goes dead as soon as another project refreshes -
which is exactly why the health check kept failing with
"invalid refresh_token" while Withings2Garmin worked fine.

Tokens are read from, and written back to, the shared token bridge when one
is configured, so every consumer sees the same rotation:

    WITHINGS_TOKEN_URL       e.g. https://klaanisodat.fi/api/withings-token
    WITHINGS_BRIDGE_SECRET   sent as "Authorization: Bearer <secret>"

With WITHINGS_TOKEN_URL unset it falls back to a local token file, which is
the old single-PC behaviour.

API credentials come from WITHINGS_CLIENT_ID / WITHINGS_CLIENT_SECRET, else
a config.json in the token directory.
"""
import json
import logging
import os
import time
from pathlib import Path

from . import bridge

logger = logging.getLogger(__name__)

__all__ = ["get_access_token", "load_tokens", "save_tokens", "get_config",
           "token_dir", "bridge"]

DEFAULT_TOKEN_DIR = "~/.withings"

# Refresh this many seconds before the token actually expires, so a slow call
# does not start with a valid token and finish with an expired one.
EXPIRY_MARGIN = 300

TOKEN_URL = "https://wbsapi.withings.net/v2/oauth2"


def token_dir(directory=None) -> Path:
    """
    Resolve the directory holding tokens.json and config.json.

    Args:
        directory: explicit path, or None to use WITHINGS_TOKENS / the default.

    Returns:
        Path: the token directory.
    """
    raw = directory or os.environ.get("WITHINGS_TOKENS") or DEFAULT_TOKEN_DIR
    return Path(raw).expanduser()


def get_config(directory=None) -> dict:
    """
    Return the Withings API client credentials.

    Returns:
        dict: with client_id and client_secret.

    Raises:
        RuntimeError: when neither the environment nor a config file has them.
    """
    client_id = os.environ.get("WITHINGS_CLIENT_ID")
    client_secret = os.environ.get("WITHINGS_CLIENT_SECRET")
    if client_id and client_secret:
        return {"client_id": client_id, "client_secret": client_secret}

    config_file = token_dir(directory) / "config.json"
    if config_file.exists():
        try:
            config = json.loads(config_file.read_text())
            if config.get("client_id") and config.get("client_secret"):
                return config
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Could not read {config_file}: {e}")

    raise RuntimeError(
        "No Withings API credentials. Set WITHINGS_CLIENT_ID and "
        f"WITHINGS_CLIENT_SECRET, or provide {config_file}."
    )


def load_tokens(directory=None) -> dict:
    """
    Load the current tokens, preferring the bridge.

    The bridge copy wins because refresh tokens rotate: a local file that
    another machine has since refreshed past is worthless.

    Returns:
        dict: the stored tokens, or {} when none are available.
    """
    store = token_dir(directory)

    fetched = bridge.fetch_tokens(store)
    if fetched:
        return fetched

    token_file = store / "tokens.json"
    if token_file.exists():
        try:
            return json.loads(token_file.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Could not read {token_file}: {e}")
    return {}


def save_tokens(tokens: dict, directory=None):
    """
    Persist tokens locally and publish them to the bridge.

    Publishing is what keeps the other consumers alive: skip it and the next
    project to run holds a refresh token this rotation just invalidated.
    """
    store = token_dir(directory)
    store.mkdir(parents=True, exist_ok=True)
    token_file = store / "tokens.json"

    token_file.write_text(json.dumps(tokens, indent=2))
    bridge.restrict(token_file)

    bridge.push_tokens(tokens)


def _expired(tokens: dict) -> bool:
    """True when the access token is missing, expired, or nearly expired."""
    if not tokens.get("access_token"):
        return True
    expires_at = tokens.get("expires_at")
    if not expires_at:
        return True
    return time.time() + EXPIRY_MARGIN >= float(expires_at)


def refresh(tokens: dict, directory=None, config=None) -> dict:
    """
    Exchange the refresh token for a new pair and store the result.

    Args:
        tokens: the current tokens, containing refresh_token.
        directory: override the token directory.
        config: client credentials, or None to resolve them.

    Returns:
        dict: the refreshed tokens.

    Raises:
        RuntimeError: when Withings rejects the refresh token.
    """
    import requests

    if not tokens.get("refresh_token"):
        raise RuntimeError("No Withings refresh token available; "
                           "re-authorisation is required.")

    config = config or get_config(directory)
    response = requests.post(TOKEN_URL, data={
        "action": "requesttoken",
        "grant_type": "refresh_token",
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "refresh_token": tokens["refresh_token"],
    }, timeout=30)

    data = response.json()
    if data.get("status") != 0:
        raise RuntimeError(f"Withings token refresh failed: {data}")

    body = data["body"]
    refreshed = {
        "access_token": body["access_token"],
        "refresh_token": body["refresh_token"],
        "token_type": body.get("token_type", tokens.get("token_type", "Bearer")),
        "expires_in": body["expires_in"],
        "expires_at": int(time.time() + body["expires_in"]),
        "userid": body.get("userid", tokens.get("userid")),
        "scope": body.get("scope", tokens.get("scope")),
    }

    save_tokens(refreshed, directory)
    logger.info("Withings token refreshed and published.")
    return refreshed


def get_access_token(directory=None, config=None) -> str:
    """
    Return a valid Withings access token, refreshing it when needed.

    Returns:
        str: a usable access token.

    Raises:
        RuntimeError: when no tokens exist or the refresh is rejected, both of
        which mean the account must be authorised again.
    """
    tokens = load_tokens(directory)
    if not tokens:
        raise RuntimeError(
            "No Withings tokens found. Authorise the account first "
            "(see .withings/oauth_helper.py) or configure WITHINGS_TOKEN_URL."
        )

    if not _expired(tokens):
        return tokens["access_token"]

    logger.info("Withings access token expired; refreshing.")
    return refresh(tokens, directory, config)["access_token"]
