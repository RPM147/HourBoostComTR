import hashlib
import hmac
import io
import json
import unittest
import urllib.error

import shopier
from payment_verification import (
    OrderValidationError,
    extract_single_token,
    parse_money,
    validate_canonical_order,
)


TOKEN = "HB-" + "A" * 32
PRODUCTS = {
    "basic-id": ("basic", 29.99),
    "premium-id": ("premium", 59.99),
}


def valid_order(order_id="order-1", token=TOKEN, product_id="basic-id"):
    price = "29.99" if product_id == "basic-id" else "59.99"
    return {
        "id": order_id,
        "paymentStatus": "paid",
        "currency": "TRY",
        "note": f"HourBoost {token}",
        "lineItems": [{
            "productId": product_id,
            "quantity": 1,
            "price": price,
            "total": price,
        }],
        "totals": {
            "subtotal": price,
            "shipping": "0.00",
            "discount": "0.00",
            "total": price,
        },
        "discounts": [],
    }


class FakeResponse:
    def __init__(self, payload, headers=None, status=200):
        self._raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.headers = headers or {}
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        return self._raw[:size]


class PaymentVerificationUnitTests(unittest.TestCase):
    def test_hmac_accepts_only_exact_hex_signature(self):
        body = b'{"id":"order-1"}'
        secret = "webhook-secret"
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertTrue(shopier.verify_webhook(body, signature, secret))
        self.assertFalse(shopier.verify_webhook(body + b" ", signature, secret))
        self.assertFalse(shopier.verify_webhook(body, "not-hex", secret))
        self.assertFalse(shopier.verify_webhook(body, "", secret))
        self.assertFalse(shopier.verify_webhook(body, signature, ""))

    def test_token_parser_rejects_legacy_and_multiple_tokens(self):
        self.assertEqual(extract_single_token(f"note {TOKEN}"), TOKEN)
        with self.assertRaisesRegex(OrderValidationError, "token_missing"):
            extract_single_token("HB-ABC123")
        with self.assertRaisesRegex(OrderValidationError, "token_multiple"):
            extract_single_token(f"{TOKEN} and {TOKEN}")

    def test_money_parser_rejects_rounding_and_non_finite_values(self):
        self.assertEqual(str(parse_money("29.990")), "29.99")
        for value in ("29.991", "NaN", "Infinity", -1, True, None):
            with self.assertRaises(OrderValidationError):
                parse_money(value)

    def test_canonical_order_success(self):
        result = validate_canonical_order(
            valid_order(), expected_order_id="order-1", products=PRODUCTS
        )
        self.assertEqual(result.plan, "basic")
        self.assertEqual(result.amount_minor, 2999)
        self.assertEqual(result.token, TOKEN)
        self.assertIsNone(result.token_error)

    def test_canonical_order_fails_closed_on_authorizing_fields(self):
        mutations = [
            ("payment_not_paid", lambda o: o.update(paymentStatus="unpaid")),
            ("currency_mismatch", lambda o: o.update(currency="USD")),
            ("quantity_mismatch", lambda o: o["lineItems"][0].update(quantity=2)),
            ("product_unknown", lambda o: o["lineItems"][0].update(productId="x")),
            ("line_total_mismatch", lambda o: o["lineItems"][0].update(total="1.00")),
            ("order_total_mismatch", lambda o: o["totals"].update(total="1.00")),
            ("shipping_not_allowed", lambda o: o["totals"].update(shipping="1.00")),
            ("discount_not_allowed", lambda o: o["totals"].update(discount="1.00")),
            ("unexpected_line_items", lambda o: o["lineItems"].append(dict(o["lineItems"][0]))),
        ]
        for reason, mutate in mutations:
            with self.subTest(reason=reason):
                order = valid_order()
                mutate(order)
                with self.assertRaises(OrderValidationError) as ctx:
                    validate_canonical_order(
                        order, expected_order_id="order-1", products=PRODUCTS
                    )
                self.assertEqual(ctx.exception.reason, reason)

    def test_missing_token_is_reported_after_financial_validation(self):
        order = valid_order()
        order["note"] = "no code"
        result = validate_canonical_order(
            order, expected_order_id="order-1", products=PRODUCTS
        )
        self.assertIsNone(result.token)
        self.assertEqual(result.token_error, "token_missing")

    def test_api_client_builds_fixed_origin_request(self):
        captured = {}

        def transport(req, timeout):
            captured["url"] = req.full_url
            captured["auth"] = req.get_header("Authorization")
            captured["timeout"] = timeout
            return FakeResponse(valid_order())

        result = shopier.get_order("test-pat", "order-1", transport=transport)
        self.assertEqual(result["id"], "order-1")
        self.assertEqual(captured["url"], "https://api.shopier.com/v1/orders/order-1")
        self.assertEqual(captured["auth"], "Bearer test-pat")

    def test_api_client_rejects_order_id_injection(self):
        for order_id in ("../orders", "x/y", "x?y", "x\ny", "şipariş"):
            with self.subTest(order_id=order_id):
                with self.assertRaises(shopier.ShopierAPIError) as ctx:
                    shopier.get_order("pat", order_id, transport=lambda *_: None)
                self.assertEqual(ctx.exception.reason, "invalid_order_id")

    def test_api_client_does_not_follow_redirects(self):
        def transport(req, timeout):
            raise urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                {"Location": "https://evil.invalid/steal"},
                io.BytesIO(b""),
            )

        with self.assertRaises(shopier.ShopierAPIError) as ctx:
            shopier.get_order("pat", "order-1", transport=transport)
        self.assertEqual(ctx.exception.reason, "redirect_rejected")
        self.assertFalse(ctx.exception.retryable)

    def test_api_error_classification_and_retry_after(self):
        def transport(req, timeout):
            raise urllib.error.HTTPError(
                req.full_url, 429, "Rate limited", {"Retry-After": "32"}, io.BytesIO(b"PII")
            )

        with self.assertRaises(shopier.ShopierAPIError) as ctx:
            shopier.get_order("pat", "order-1", transport=transport)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.retry_after, 32)
        self.assertTrue(ctx.exception.retryable)
        self.assertNotIn("PII", str(ctx.exception))

    def test_api_response_size_and_shape_are_bounded(self):
        def too_large(req, timeout):
            return FakeResponse(b"x", headers={"Content-Length": str(shopier.MAX_RESPONSE_BYTES + 1)})

        with self.assertRaises(shopier.ShopierAPIError) as ctx:
            shopier.get_order("pat", "order-1", transport=too_large)
        self.assertEqual(ctx.exception.reason, "response_too_large")

        with self.assertRaises(shopier.ShopierAPIError) as ctx:
            shopier.get_order(
                "pat", "order-1", transport=lambda *_: FakeResponse(["not", "object"])
            )
        self.assertEqual(ctx.exception.reason, "invalid_response")


if __name__ == "__main__":
    unittest.main()
