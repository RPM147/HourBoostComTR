import io
import json
import unittest
import urllib.error
from unittest import mock

from steam_profile import MAX_PROFILE_RESPONSE_BYTES, SteamProfileResolver


STEAM_ID = "76561198000000001"
OTHER_STEAM_ID = "76561198000000002"
AVATAR = "https://avatars.steamstatic.com/abcdef_full.jpg"


class _Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


class _Response:
    def __init__(self, payload):
        self._stream = io.BytesIO(payload)

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _api_payload(steam_id=STEAM_ID, *, private=False):
    return json.dumps({
        "response": {
            "players": [{
                "steamid": steam_id,
                "communityvisibilitystate": 1 if private else 3,
                "personaname": "Persona Name",
                "avatarfull": AVATAR,
            }]
        }
    }).encode()


def _xml_payload(name="XML Persona"):
    return (
        "<profile><steamID>" + name + "</steamID>"
        "<avatarFull>https://avatars.steamstatic.com/xml_full.jpg</avatarFull>"
        "</profile>"
    ).encode()


class SteamProfileResolverTests(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.logger = mock.Mock()

    def resolver(self, opener, **overrides):
        options = {
            "opener": opener,
            "logger": self.logger,
            "monotonic": self.clock,
            "cache_ttl": 10,
            "stale_ttl": 100,
            "failure_cooldown": 5,
            "auth_cooldown": 60,
            "max_entries": 3,
            "xml_fallback_enabled": True,
        }
        options.update(overrides)
        return SteamProfileResolver(**options)

    def test_web_api_success_is_cached_and_private_profile_is_accepted(self):
        opener = mock.Mock(return_value=_Response(_api_payload(private=True)))
        resolver = self.resolver(opener)

        first = resolver.resolve(STEAM_ID, api_key="valid-key")
        second = resolver.resolve(STEAM_ID, api_key="valid-key")

        self.assertEqual(first["name"], "Persona Name")
        self.assertEqual(first["avatar"], AVATAR)
        self.assertEqual(second, first)
        opener.assert_called_once()

    def test_web_api_403_trips_global_auth_circuit_without_logging_key(self):
        calls = []

        def opener(request, timeout, **kwargs):
            calls.append((request.full_url, timeout))
            self.assertFalse(kwargs["allow_redirects"])
            if request.full_url.startswith("https://api.steampowered.com"):
                raise urllib.error.HTTPError(
                    request.full_url,
                    403,
                    "Forbidden",
                    {},
                    None,
                )
            return _Response(_xml_payload())

        resolver = self.resolver(opener)
        resolver.resolve(STEAM_ID, api_key="SECRET-API-KEY")
        resolver.resolve(OTHER_STEAM_ID, api_key="SECRET-API-KEY")

        api_calls = [url for url, _ in calls if "api.steampowered.com" in url]
        xml_calls = [url for url, _ in calls if "steamcommunity.com" in url]
        self.assertEqual(len(api_calls), 1)
        self.assertEqual(len(xml_calls), 2)
        rendered_logs = " ".join(
            str(part)
            for call in self.logger.warning.call_args_list
            for part in call.args
        )
        self.assertNotIn("SECRET-API-KEY", rendered_logs)
        self.assertNotIn("api.steampowered.com", rendered_logs)

    def test_xml_429_uses_negative_cache_instead_of_request_storm(self):
        calls = []

        def opener(request, timeout, **kwargs):
            calls.append((request.full_url, timeout))
            self.assertFalse(kwargs["allow_redirects"])
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {"Retry-After": "30"},
                None,
            )

        resolver = self.resolver(opener)
        fallback = {"name": "login_name"}
        first = resolver.resolve(STEAM_ID, fallback_profile=fallback)
        second = resolver.resolve(STEAM_ID, fallback_profile=fallback)

        self.assertEqual(first["name"], "login_name")
        self.assertEqual(second, first)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.logger.warning.call_count, 1)

    def test_timeout_is_cooled_down_and_does_not_escape(self):
        opener = mock.Mock(side_effect=TimeoutError("synthetic timeout"))
        resolver = self.resolver(opener)

        first = resolver.resolve(
            STEAM_ID,
            fallback_profile={"name": "fallback"},
        )
        second = resolver.resolve(
            STEAM_ID,
            fallback_profile={"name": "fallback"},
        )

        self.assertEqual(first["name"], "fallback")
        self.assertEqual(second, first)
        opener.assert_called_once()

    def test_last_known_good_is_returned_after_transient_api_failure(self):
        opener = mock.Mock(return_value=_Response(_api_payload()))
        resolver = self.resolver(opener)
        expected = resolver.resolve(STEAM_ID, api_key="valid-key")
        self.clock.value += 11
        opener.side_effect = urllib.error.HTTPError(
            "redacted",
            503,
            "Unavailable",
            {},
            None,
        )

        actual = resolver.resolve(STEAM_ID, api_key="valid-key")

        self.assertEqual(actual, expected)
        self.assertEqual(opener.call_count, 2)

    def test_cm_persona_precedes_external_providers(self):
        opener = mock.Mock()
        resolver = self.resolver(opener)

        profile = resolver.resolve(
            STEAM_ID,
            api_key="unused-key",
            live_profile_loader=lambda: {
                "name": "CM Persona",
                "avatar": "https://steamcdn-a.akamaihd.net/steamcommunity/"
                "public/images/avatars/ab/abcdef_full.jpg",
            },
        )

        self.assertEqual(profile["name"], "CM Persona")
        self.assertIn("steamcdn-a.akamaihd.net", profile["avatar"])
        opener.assert_not_called()

    def test_partial_cm_persona_is_cached_for_fresh_ttl(self):
        opener = mock.Mock()
        live_loader = mock.Mock(return_value={"name": "Name Only"})
        resolver = self.resolver(opener, xml_fallback_enabled=False)

        first = resolver.resolve(
            STEAM_ID,
            live_profile_loader=live_loader,
        )
        second = resolver.resolve(
            STEAM_ID,
            live_profile_loader=live_loader,
        )

        self.assertEqual(first["name"], "Name Only")
        self.assertEqual(second, first)
        live_loader.assert_called_once()
        opener.assert_not_called()

    def test_untrusted_avatar_host_is_rejected(self):
        payload = json.dumps({
            "response": {"players": [{
                "personaname": "Safe Name",
                "avatarfull": "https://evil.example/tracker.png",
            }]}
        }).encode()
        opener = mock.Mock(return_value=_Response(payload))
        resolver = self.resolver(opener, xml_fallback_enabled=False)

        profile = resolver.resolve(STEAM_ID, api_key="valid-key")

        self.assertEqual(profile["name"], "Safe Name")
        self.assertEqual(profile["avatar"], "")

    def test_current_fastly_steam_avatar_host_is_accepted(self):
        avatar = "https://avatars.fastly.steamstatic.com/abcdef_full.jpg"
        payload = json.dumps({
            "response": {"players": [{
                "personaname": "Fastly Persona",
                "avatarfull": avatar,
            }]}
        }).encode()
        resolver = self.resolver(mock.Mock(return_value=_Response(payload)))

        profile = resolver.resolve(STEAM_ID, api_key="valid-key")

        self.assertEqual(profile["avatar"], avatar)

    def test_oversized_responses_are_rejected_without_raising(self):
        opener = mock.Mock(
            return_value=_Response(b"x" * (MAX_PROFILE_RESPONSE_BYTES + 1))
        )
        resolver = self.resolver(opener, xml_fallback_enabled=False)

        profile = resolver.resolve(
            STEAM_ID,
            api_key="valid-key",
            fallback_profile={"name": "fallback"},
        )

        self.assertEqual(profile["name"], "fallback")
        self.assertEqual(self.logger.warning.call_count, 1)


if __name__ == "__main__":
    unittest.main()
