"""
Shopier entegrasyonu — PAT tabanlı yeni yöntem.
Musteri Shopier dukkanindan satin alir -> order.fulfilled webhook gelir ->
kullanici adi alinip plan aktif edilir.
"""
import hmac
import hashlib
import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

API_BASE = "https://api.shopier.com/v1"


def _api_request(pat, method, path, body=None):
    url = API_BASE + path
    headers = {
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "HourBoost/1.0",
    }
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        logger.error(
            "Shopier API %s %s -> %s: %s",
            method, path, e.code,
            e.read().decode("utf-8", errors="replace"),
        )
        return None
    except Exception as e:
        logger.error("Shopier API hatasi: %s", e)
        return None


def get_order(pat, order_id):
    """Tek siparis detayi."""
    return _api_request(pat, "GET", f"/orders/{order_id}")


def verify_webhook(raw_body: bytes, signature_header: str, webhook_secret: str) -> bool:
    """
    Shopier webhook imzasini dogrular.
    Header: Shopier-Signature  (HMAC-SHA256, hex digest)
    """
    if not webhook_secret:
        logger.warning("Webhook secret tanimli degil, dogrulama reddedildi (Fail-Closed).")
        return False

    if not signature_header:
        logger.warning("Webhook isteginde imza headeri yok!")
        return False

    # Python 3 — dogru kullanim: hmac.new(key, msg, digestmod)
    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    is_valid = hmac.compare_digest(
        signature_header.lower(),
        expected.lower(),
    )

    if not is_valid:
        logger.warning("Webhook imza dogrulanamadi!")

    return is_valid


def extract_plan(product_id, basic_id, premium_id):
    """Shopier urun ID'sinden plan adi doner."""
    pid = str(product_id)
    if pid == str(basic_id):
        return "basic"
    if pid == str(premium_id):
        return "premium"
    return None