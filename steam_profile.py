"""Bounded, secret-safe Steam profile resolution.

The logged-in CM worker is the preferred source for the account currently
connected to Steam.  The official Web API fills missing fields, while the
deprecated Community XML endpoint is retained only as a rate-limited last
resort.  All state in this module is best-effort presentation state: profile
failures must never affect authentication or boosting.
"""

from collections import OrderedDict
from contextlib import suppress
import json
import math
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


STEAM_ID_RE = re.compile(r"\d{17}")
MAX_PROFILE_RESPONSE_BYTES = 256 * 1024
_ALLOWED_AVATAR_HOSTS = frozenset({
    "avatars.steamstatic.com",
    "avatars.fastly.steamstatic.com",
    "cdn.cloudflare.steamstatic.com",
    "steamcdn-a.akamaihd.net",
})


def valid_steam_id(value):
    """Return a canonical SteamID64 or ``None`` for malformed values."""
    candidate = str(value or "").strip()
    return candidate if STEAM_ID_RE.fullmatch(candidate) else None


def _clean_name(value):
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", "", value).strip()[:100]


def _safe_avatar_url(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    try:
        parsed = urllib.parse.urlparse(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_AVATAR_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            return ""
    except (TypeError, ValueError):
        return ""
    return value[:512]


def _normalize_profile(steam_id, profile):
    steam_id = valid_steam_id(steam_id)
    if steam_id is None or not isinstance(profile, dict):
        return {}
    return {
        "steam_id": steam_id,
        "name": _clean_name(profile.get("name")),
        "avatar": _safe_avatar_url(profile.get("avatar")),
        # Never trust or relay a provider-controlled profile URL.
        "profile_url": f"https://steamcommunity.com/profiles/{steam_id}",
    }


def _has_profile_data(profile):
    return bool(profile and (profile.get("name") or profile.get("avatar")))


def _profile_complete(profile):
    return bool(profile and profile.get("name") and profile.get("avatar"))


def _merge_profiles(*profiles):
    merged = {}
    for profile in profiles:
        if not profile:
            continue
        if not merged.get("steam_id") and profile.get("steam_id"):
            merged["steam_id"] = profile["steam_id"]
        if not merged.get("name") and profile.get("name"):
            merged["name"] = profile["name"]
        if not merged.get("avatar") and profile.get("avatar"):
            merged["avatar"] = profile["avatar"]
        if not merged.get("profile_url") and profile.get("profile_url"):
            merged["profile_url"] = profile["profile_url"]
    if merged.get("steam_id"):
        merged.setdefault("name", "")
        merged.setdefault("avatar", "")
        merged.setdefault(
            "profile_url",
            f"https://steamcommunity.com/profiles/{merged['steam_id']}",
        )
    return merged


class SteamProfileResolver:
    """Resolve profiles with bounded cache and provider circuit breakers."""

    def __init__(
        self,
        *,
        opener,
        logger,
        monotonic=None,
        cache_ttl=900,
        stale_ttl=86400,
        failure_cooldown=60,
        auth_cooldown=3600,
        max_entries=500,
        xml_fallback_enabled=True,
    ):
        self._opener = opener
        self._logger = logger
        self._monotonic = monotonic or time.monotonic
        self._cache_ttl = self._positive(cache_ttl, "cache_ttl")
        self._stale_ttl = max(
            self._cache_ttl,
            self._positive(stale_ttl, "stale_ttl"),
        )
        self._failure_cooldown = self._positive(
            failure_cooldown,
            "failure_cooldown",
        )
        self._auth_cooldown = self._positive(auth_cooldown, "auth_cooldown")
        self._max_entries = int(self._positive(max_entries, "max_entries"))
        self._xml_fallback_enabled = bool(xml_fallback_enabled)
        self._lock = threading.RLock()
        self._cache = OrderedDict()
        self._negative = OrderedDict()
        self._provider_state = {
            "web_api_auth": {"until": 0.0, "failures": 0},
            "web_api_transient": {"until": 0.0, "failures": 0},
            "community_xml": {"until": 0.0, "failures": 0},
            "cm_persona": {"until": 0.0, "failures": 0},
        }

    @staticmethod
    def _positive(value, name):
        value = float(value)
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be positive")
        return value

    def clear(self):
        """Clear volatile state; intended for deterministic tests."""
        with self._lock:
            self._cache.clear()
            self._negative.clear()
            for state in self._provider_state.values():
                state["until"] = 0.0
                state["failures"] = 0

    def _now(self):
        now = float(self._monotonic())
        if not math.isfinite(now):
            raise ValueError("monotonic clock must be finite")
        return now

    def _bounded_put(self, mapping, key, value):
        mapping.pop(key, None)
        mapping[key] = value
        while len(mapping) > self._max_entries:
            mapping.popitem(last=False)

    def _cached(self, steam_id, now):
        with self._lock:
            entry = self._cache.get(steam_id)
            if entry is None:
                return {}, False
            if now >= entry["stale_until"]:
                self._cache.pop(steam_id, None)
                return {}, False
            self._cache.move_to_end(steam_id)
            return dict(entry["profile"]), now < entry["fresh_until"]

    def _cache_profile(self, steam_id, profile, now):
        profile = _normalize_profile(steam_id, profile)
        if not _has_profile_data(profile):
            return
        with self._lock:
            self._bounded_put(self._cache, steam_id, {
                "profile": dict(profile),
                "fresh_until": now + self._cache_ttl,
                "stale_until": now + self._stale_ttl,
            })
            self._negative.pop(steam_id, None)

    def _negative_active(self, steam_id, now):
        with self._lock:
            until = self._negative.get(steam_id, 0.0)
            if until <= now:
                self._negative.pop(steam_id, None)
                return False
            self._negative.move_to_end(steam_id)
            return True

    def _mark_negative(self, steam_id, now):
        with self._lock:
            self._bounded_put(
                self._negative,
                steam_id,
                now + self._failure_cooldown,
            )

    def _provider_available(self, provider, now):
        with self._lock:
            return self._provider_state[provider]["until"] <= now

    def _provider_success(self, *providers):
        with self._lock:
            for provider in providers:
                state = self._provider_state[provider]
                state["until"] = 0.0
                state["failures"] = 0

    def _trip_provider(
        self,
        provider,
        now,
        *,
        status=None,
        error_class=None,
        fixed_cooldown=None,
        retry_after=None,
    ):
        with self._lock:
            state = self._provider_state[provider]
            if state["until"] > now:
                return
            state["failures"] = min(int(state["failures"]) + 1, 8)
            if fixed_cooldown is not None:
                cooldown = float(fixed_cooldown)
            else:
                cooldown = min(
                    self._failure_cooldown * (2 ** (state["failures"] - 1)),
                    self._failure_cooldown * 16,
                )
            if retry_after is not None:
                cooldown = max(cooldown, min(float(retry_after), 3600.0))
            state["until"] = now + cooldown

        # Deliberately omit URL and exception text: Web API URLs contain the key.
        self._logger.warning(
            "steam_profile.provider_cooldown provider=%s status=%s "
            "error_class=%s cooldown_seconds=%d",
            provider,
            status if status is not None else "none",
            error_class or "none",
            int(math.ceil(cooldown)),
        )

    @staticmethod
    def _retry_after(error):
        try:
            raw = error.headers.get("Retry-After")
            value = int(raw)
            return value if value > 0 else None
        except (AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    def _read_limited(response):
        payload = response.read(MAX_PROFILE_RESPONSE_BYTES + 1)
        if len(payload) > MAX_PROFILE_RESPONSE_BYTES:
            raise ValueError("Steam profile response exceeded size limit")
        return payload

    def _fetch_web_api(self, steam_id, api_key):
        query = urllib.parse.urlencode({
            "key": api_key,
            "steamids": steam_id,
        })
        request = urllib.request.Request(
            "https://api.steampowered.com/ISteamUser/"
            f"GetPlayerSummaries/v2/?{query}",
            headers={"User-Agent": "HourBoost/1.0"},
        )
        with self._opener(
            request,
            timeout=6,
            allow_redirects=False,
        ) as response:
            payload = self._read_limited(response)
        data = json.loads(payload.decode("utf-8"))
        players = data.get("response", {}).get("players", [])
        if not isinstance(players, list) or not players:
            return {}
        player = players[0]
        if not isinstance(player, dict):
            return {}
        return _normalize_profile(steam_id, {
            "name": player.get("personaname"),
            "avatar": player.get("avatarfull"),
        })

    def _fetch_community_xml(self, steam_id):
        request = urllib.request.Request(
            f"https://steamcommunity.com/profiles/{steam_id}/?xml=1",
            headers={"User-Agent": "HourBoost/1.0"},
        )
        with self._opener(
            request,
            timeout=4,
            allow_redirects=False,
        ) as response:
            payload = self._read_limited(response)
        root = ET.fromstring(payload.decode("utf-8"))
        return _normalize_profile(steam_id, {
            "name": root.findtext("steamID"),
            "avatar": root.findtext("avatarFull"),
        })

    def resolve(
        self,
        steam_id,
        *,
        api_key=None,
        live_profile_loader=None,
        fallback_profile=None,
    ):
        """Return the best available profile without raising provider errors."""
        steam_id = valid_steam_id(steam_id)
        if steam_id is None:
            return {}

        now = self._now()
        cached, fresh = self._cached(steam_id, now)
        # Partial provider data (for example a private profile with a name but
        # no avatar) is still a valid cached result. Re-query only after its
        # fresh TTL instead of turning UI polling into repeated CM IPC.
        if fresh and _has_profile_data(cached):
            return cached

        fallback = _normalize_profile(steam_id, fallback_profile or {})
        candidate = cached
        provider_returned_data = False

        # A connected account may have been established after a previous
        # external-provider failure, so CM is attempted independently of the
        # per-SteamID negative cache.
        if (
            live_profile_loader is not None
            and self._provider_available("cm_persona", now)
        ):
            try:
                live = _normalize_profile(steam_id, live_profile_loader() or {})
                self._provider_success("cm_persona")
                if _has_profile_data(live):
                    provider_returned_data = True
                    candidate = _merge_profiles(live, candidate)
            except Exception as error:
                self._trip_provider(
                    "cm_persona",
                    now,
                    error_class=type(error).__name__,
                )

        if provider_returned_data and _profile_complete(candidate):
            self._cache_profile(steam_id, candidate, now)
            return candidate

        if self._negative_active(steam_id, now):
            return _merge_profiles(candidate, fallback)

        api_key = api_key.strip() if isinstance(api_key, str) else ""
        api_available = (
            api_key
            and self._provider_available("web_api_auth", now)
            and self._provider_available("web_api_transient", now)
        )
        if api_available:
            try:
                api_profile = self._fetch_web_api(steam_id, api_key)
                self._provider_success("web_api_auth", "web_api_transient")
                if _has_profile_data(api_profile):
                    provider_returned_data = True
                    candidate = _merge_profiles(candidate, api_profile)
            except urllib.error.HTTPError as error:
                status = int(error.code)
                retry_after = self._retry_after(error) if status == 429 else None
                with suppress(Exception):
                    error.close()
                if status in (401, 403):
                    self._trip_provider(
                        "web_api_auth",
                        now,
                        status=status,
                        error_class=type(error).__name__,
                        fixed_cooldown=self._auth_cooldown,
                    )
                else:
                    self._trip_provider(
                        "web_api_transient",
                        now,
                        status=status,
                        error_class=type(error).__name__,
                        retry_after=retry_after,
                    )
            except Exception as error:
                self._trip_provider(
                    "web_api_transient",
                    now,
                    error_class=type(error).__name__,
                )

        if _profile_complete(candidate):
            if provider_returned_data:
                self._cache_profile(steam_id, candidate, now)
            return candidate

        # Last-known-good provider data is safer and cheaper than the
        # deprecated XML endpoint.  The account login name is not necessarily
        # the public persona name, however, so merge that display fallback only
        # after XML had a chance to supply the real value.
        if (
            not _profile_complete(candidate)
            and self._xml_fallback_enabled
            and self._provider_available("community_xml", now)
        ):
            try:
                xml_profile = self._fetch_community_xml(steam_id)
                self._provider_success("community_xml")
                if _has_profile_data(xml_profile):
                    provider_returned_data = True
                    candidate = _merge_profiles(candidate, xml_profile)
            except urllib.error.HTTPError as error:
                status = int(error.code)
                retry_after = self._retry_after(error) if status == 429 else None
                with suppress(Exception):
                    error.close()
                self._trip_provider(
                    "community_xml",
                    now,
                    status=status,
                    error_class=type(error).__name__,
                    retry_after=retry_after,
                )
            except Exception as error:
                self._trip_provider(
                    "community_xml",
                    now,
                    error_class=type(error).__name__,
                )

        candidate = _merge_profiles(candidate, fallback)

        if provider_returned_data:
            self._cache_profile(steam_id, candidate, now)
        else:
            self._mark_negative(steam_id, now)
        return candidate if _has_profile_data(candidate) else {}
