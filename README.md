# withings_auth

One shared way to get a valid Withings access token, so each project stops
reimplementing "load tokens, refresh if expired, save them again".

```python
from withings_auth import get_access_token
token = get_access_token()
```

## Why this exists

Withings issues **single-use refresh tokens**. Every refresh rotates the pair,
so a token file that one project keeps locally goes dead the moment another
project refreshes. That is exactly why a health check could fail with
`invalid refresh_token` while another tool on the same account worked fine.

This package makes the refresh a shared operation: it reads the newest tokens
from a bridge endpoint, and publishes every rotation back to it.

## Configuration

| Variable | Purpose |
|---|---|
| `WITHINGS_TOKEN_URL` | bridge endpoint, e.g. `https://example.com/api/withings-token` |
| `WITHINGS_BRIDGE_SECRET` | sent as `Authorization: Bearer ...` |
| `WITHINGS_CLIENT_ID` / `WITHINGS_CLIENT_SECRET` | API credentials |
| `WITHINGS_TOKENS` | token directory (default `~/.withings`) |

With `WITHINGS_TOKEN_URL` unset the bridge is inert and only the local token
file is used - the old single-PC behaviour. Bridge failures are logged, never
raised: an outage falls back to local tokens rather than breaking a sync.

Client credentials may also live in `config.json` in the token directory, or
be passed directly as `config=` for projects with their own layout.

## Bridge contract

```
GET  -> {"access_token": "...", "refresh_token": "...", "expires_at": 1234567890, ...}
        404 before anything is stored
PUT  <- the same shape
```

## API

| Function | Purpose |
|---|---|
| `get_access_token(directory=None, config=None)` | a valid token, refreshing if needed |
| `load_tokens(directory=None)` | newest tokens: bridge, else local |
| `save_tokens(tokens, directory=None)` | save locally and publish |
| `refresh(tokens, directory=None, config=None)` | rotate and store |
| `get_config(directory=None)` | resolve client credentials |

Tokens are refreshed 5 minutes before expiry, so a slow call cannot start
valid and finish expired.

## Security

These tokens grant access to your Withings health data. The token file is
written `0600` where the OS supports it. Keep `WITHINGS_BRIDGE_SECRET` out of
version control - it belongs in an environment variable.

## Tests

```
python -m unittest discover tests
```

20 tests, no network and no Withings account required.
