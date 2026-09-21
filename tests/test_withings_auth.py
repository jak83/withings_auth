"""
Tests for withings_auth. No network, no Withings account.
"""
import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import withings_auth
from withings_auth import bridge

BRIDGE_ENV = {
    "WITHINGS_TOKEN_URL": "https://klaanisodat.fi/api/withings-token",
    "WITHINGS_BRIDGE_SECRET": "test-secret",
}

CONFIG_ENV = {
    "WITHINGS_CLIENT_ID": "cid",
    "WITHINGS_CLIENT_SECRET": "csecret",
}


def _tokens(access="acc", refresh="ref", expires_in=10800, offset=0):
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "expires_at": int(time.time() + offset),
        "userid": "42",
    }


def _response(status=200, payload=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else {}
    resp.raise_for_status.return_value = None
    return resp


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.store = Path(__file__).resolve().parent / "_tmp_withings"
        if self.store.exists():
            shutil.rmtree(self.store)
        self.store.mkdir()

    def tearDown(self):
        if self.store.exists():
            shutil.rmtree(self.store)

    def _write(self, tokens):
        (self.store / "tokens.json").write_text(json.dumps(tokens))


class TestExpiry(StoreTestCase):
    """Expiry drives whether a refresh happens at all."""

    def test_valid_token_is_not_expired(self):
        self.assertFalse(withings_auth._expired(_tokens(offset=10800)))

    def test_past_expiry_is_expired(self):
        self.assertTrue(withings_auth._expired(_tokens(offset=-10)))

    def test_expiring_within_the_margin_counts_as_expired(self):
        """A call must not start valid and finish expired."""
        self.assertTrue(withings_auth._expired(_tokens(offset=60)))

    def test_missing_fields_count_as_expired(self):
        self.assertTrue(withings_auth._expired({}))
        self.assertTrue(withings_auth._expired({"access_token": "x"}))


class TestLoadTokens(StoreTestCase):
    """The bridge copy wins, because refresh tokens rotate."""

    def test_bridge_is_preferred_over_the_local_file(self):
        self._write(_tokens(access="stale", refresh="stale-ref"))
        fresh = _tokens(access="fresh", refresh="fresh-ref", offset=10800)

        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", return_value=_response(200, fresh)):
                loaded = withings_auth.load_tokens(self.store)

        self.assertEqual(loaded["access_token"], "fresh")
        # And it is cached locally for the next bridge outage.
        cached = json.loads((self.store / "tokens.json").read_text())
        self.assertEqual(cached["access_token"], "fresh")

    def test_local_file_is_used_when_the_bridge_is_off(self):
        self._write(_tokens(access="local"))
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                withings_auth.load_tokens(self.store)["access_token"], "local")

    def test_bridge_outage_falls_back_to_local(self):
        self._write(_tokens(access="local"))
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.get", side_effect=OSError("no route")):
                self.assertEqual(
                    withings_auth.load_tokens(self.store)["access_token"], "local")

    def test_nothing_anywhere_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(withings_auth.load_tokens(self.store), {})


class TestSaveTokens(StoreTestCase):
    def test_saves_locally_and_publishes(self):
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put", return_value=_response(200)) as mock_put:
                withings_auth.save_tokens(_tokens(), self.store)

        self.assertTrue((self.store / "tokens.json").exists())
        self.assertEqual(mock_put.call_args[1]["json"]["access_token"], "acc")

    def test_incomplete_tokens_are_not_published(self):
        with patch.dict(os.environ, BRIDGE_ENV, clear=True):
            with patch("requests.put") as mock_put:
                withings_auth.save_tokens({"access_token": "only"}, self.store)
            mock_put.assert_not_called()


class TestRefresh(StoreTestCase):
    """A refresh must persist AND publish, or other consumers break."""

    def _ok(self):
        return _response(200, {"status": 0, "body": {
            "access_token": "new-acc", "refresh_token": "new-ref",
            "expires_in": 10800, "userid": "42", "scope": "user.metrics"}})

    def test_publishes_the_rotated_pair(self):
        env = dict(BRIDGE_ENV, **CONFIG_ENV)
        with patch.dict(os.environ, env, clear=True):
            with patch("requests.post", return_value=self._ok()):
                with patch("requests.put", return_value=_response(200)) as mock_put:
                    result = withings_auth.refresh(_tokens(), self.store)

        self.assertEqual(result["access_token"], "new-acc")
        self.assertEqual(result["refresh_token"], "new-ref")
        published = mock_put.call_args[1]["json"]
        self.assertEqual(published["refresh_token"], "new-ref")

    def test_expires_at_is_computed(self):
        with patch.dict(os.environ, CONFIG_ENV, clear=True):
            with patch("requests.post", return_value=self._ok()):
                result = withings_auth.refresh(_tokens(), self.store)

        self.assertGreater(result["expires_at"], time.time() + 10000)

    def test_rejected_refresh_token_raises_clearly(self):
        """This is the failure that was silently breaking the health check."""
        bad = _response(200, {"status": 503,
                              "error": "Invalid Params: invalid refresh_token"})
        with patch.dict(os.environ, CONFIG_ENV, clear=True):
            with patch("requests.post", return_value=bad):
                with self.assertRaises(RuntimeError) as cm:
                    withings_auth.refresh(_tokens(), self.store)

        self.assertIn("refresh failed", str(cm.exception))

    def test_no_refresh_token_raises(self):
        with patch.dict(os.environ, CONFIG_ENV, clear=True):
            with self.assertRaises(RuntimeError):
                withings_auth.refresh({"access_token": "x"}, self.store)


class TestGetAccessToken(StoreTestCase):
    def test_valid_token_is_returned_without_refreshing(self):
        self._write(_tokens(access="still-good", offset=10800))
        with patch.dict(os.environ, {}, clear=True):
            with patch("requests.post") as mock_post:
                token = withings_auth.get_access_token(self.store)

        self.assertEqual(token, "still-good")
        mock_post.assert_not_called()

    def test_expired_token_triggers_a_refresh(self):
        self._write(_tokens(offset=-10))
        ok = _response(200, {"status": 0, "body": {
            "access_token": "refreshed", "refresh_token": "r2",
            "expires_in": 10800, "userid": "42"}})

        with patch.dict(os.environ, CONFIG_ENV, clear=True):
            with patch("requests.post", return_value=ok):
                self.assertEqual(
                    withings_auth.get_access_token(self.store), "refreshed")

    def test_no_tokens_raises_with_guidance(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                withings_auth.get_access_token(self.store)

        self.assertIn("No Withings tokens", str(cm.exception))


class TestConfig(StoreTestCase):
    def test_environment_wins(self):
        with patch.dict(os.environ, CONFIG_ENV, clear=True):
            self.assertEqual(withings_auth.get_config(self.store)["client_id"], "cid")

    def test_config_file_is_used_as_fallback(self):
        (self.store / "config.json").write_text(
            json.dumps({"client_id": "fid", "client_secret": "fsecret"}))
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(withings_auth.get_config(self.store)["client_id"], "fid")

    def test_missing_config_raises_clearly(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as cm:
                withings_auth.get_config(self.store)
        self.assertIn("WITHINGS_CLIENT_ID", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
