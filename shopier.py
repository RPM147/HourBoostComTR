"""Small, fail-closed Shopier REST API and webhook helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import socket
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request


API_BASE = "https://api.shopier.com/v1"
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 10
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class ShopierAPIError(Exception):
    """Sanitized API error safe to persist and log."""

    reason: str
    status_code: int | None = None
    retry_after: int | None = None
    retryable: bool = False

    def __str__(self) -> str:
        status = f" status={self.status_code}" if self.status_code else ""
        return f"Shopier API error: {self.reason}{status}"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_api_opener = urllib.request.build_opener(_NoRedirectHandler)


def _default_transport(req: urllib.request.Request, timeout: int):
    return _api_opener.open(req, timeout=timeout)


def _parse_retry_after(headers: Any) -> int | None:
    try:
        raw = headers.get("Retry-After")
        if raw is None:
            return None
        return max(1, min(3600, int(str(raw).strip())))
    except (AttributeError, TypeError, ValueError):
        return None


def _classify_http_error(status_code: int) -> tuple[str, bool]:
    if status_code in (301, 302, 303, 307, 308):
        return "redirect_rejected", False
    if status_code == 401:
        return "api_unauthorized", True
    if status_code == 403:
        return "api_forbidden", True
    if status_code == 404:
        return "api_not_found", True
    if status_code == 429:
        return "api_rate_limited", True
    if status_code in (500, 502, 503, 504):
        return "api_upstream_error", True
    return "api_http_error", False


def _api_request(
    pat: str,
    method: str,
    path: str,
    body: dict | None = None,
    *,
    transport: Callable | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    expect_object: bool = True,
):
    if not isinstance(pat, str) or not pat.strip():
        raise ShopierAPIError("missing_pat", retryable=True)
    if not isinstance(path, str) or not path.startswith("/"):
        raise ShopierAPIError("invalid_path")

    url = API_BASE + path
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.shopier.com"
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/v1/")
    ):
        raise ShopierAPIError("unsafe_url")

    headers = {
        "Authorization": f"Bearer {pat.strip()}",
        "Accept": "application/json",
        "User-Agent": "HourBoost-PaymentVerifier/2.0",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = transport or _default_transport

    try:
        with opener(req, timeout) as resp:
            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        raise ShopierAPIError("response_too_large", retryable=True)
                except ValueError:
                    pass
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ShopierAPIError("response_too_large", retryable=True)
    except urllib.error.HTTPError as exc:
        reason, retryable = _classify_http_error(exc.code)
        raise ShopierAPIError(
            reason,
            status_code=exc.code,
            retry_after=_parse_retry_after(exc.headers),
            retryable=retryable,
        ) from None
    except ShopierAPIError:
        raise
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        raise ShopierAPIError("transport_error", retryable=True) from None
    except Exception:
        raise ShopierAPIError("transport_error", retryable=True) from None

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ShopierAPIError("invalid_json", retryable=True) from None
    if expect_object and not isinstance(payload, dict):
        raise ShopierAPIError("invalid_response", retryable=True)
    if not expect_object and not isinstance(payload, list):
        raise ShopierAPIError("invalid_response", retryable=True)
    return payload


def get_order(
    pat: str,
    order_id: str,
    *,
    transport: Callable | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
):
    """Return one canonical Shopier Order object."""
    normalized_id = str(order_id or "").strip()
    if not _ORDER_ID_RE.fullmatch(normalized_id):
        raise ShopierAPIError("invalid_order_id")
    safe_id = urllib.parse.quote(normalized_id, safe="")
    return _api_request(
        pat,
        "GET",
        f"/orders/{safe_id}",
        transport=transport,
        timeout=timeout,
    )


def list_webhooks(
    pat: str,
    *,
    transport: Callable | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
):
    """Return configured webhook subscriptions for deployment checks."""
    return _api_request(
        pat,
        "GET",
        "/webhooks?limit=50",
        transport=transport,
        timeout=timeout,
        expect_object=False,
    )


def verify_webhook(raw_body: bytes, signature_header: str, webhook_secret: str) -> bool:
    """Verify the raw request body against Shopier's HMAC-SHA256 signature."""
    if not isinstance(webhook_secret, str) or not webhook_secret:
        return False
    if not isinstance(raw_body, bytes) or not isinstance(signature_header, str):
        return False
    signature = signature_header.strip()
    if not _SIGNATURE_RE.fullmatch(signature):
        return False

    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature.lower(), expected.lower())


def extract_plan(product_id, basic_id, premium_id):
    """Map one Shopier product ID to the local plan name."""
    pid = str(product_id)
    if pid == str(basic_id):
        return "basic"
    if pid == str(premium_id):
        return "premium"
    return None
