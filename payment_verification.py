"""Pure validation helpers for Shopier order verification.

This module deliberately has no Flask or database dependency. It turns an
untrusted Shopier API payload into a small canonical result that the database
worker can consume. No customer PII is retained or returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import re
from typing import Any, Mapping


HB_TOKEN_RE = re.compile(r"\bHB-([0-9A-Fa-f]{32})\b", re.IGNORECASE)
MONEY_QUANTUM = Decimal("0.01")
MAX_ORDER_NOTE_CHARS = 4096


class OrderValidationError(ValueError):
    """A safe, non-PII business validation failure."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class CanonicalOrder:
    order_id: str
    plan: str
    product_id: str
    amount: Decimal
    amount_minor: int
    token: str | None
    token_error: str | None


def token_fingerprint(token: str | None) -> str:
    """Return a short irreversible identifier suitable for logs."""
    if not token:
        return "none"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def extract_single_token(note: Any) -> str:
    """Extract exactly one modern HourBoost checkout token from a note."""
    if not isinstance(note, str) or not note:
        raise OrderValidationError("token_missing")
    if len(note) > MAX_ORDER_NOTE_CHARS:
        raise OrderValidationError("note_too_large")

    matches = HB_TOKEN_RE.findall(note)
    if not matches:
        raise OrderValidationError("token_missing")
    if len(matches) != 1:
        raise OrderValidationError("token_multiple")
    return "HB-" + matches[0].upper()


def parse_money(value: Any, *, reason: str = "amount_invalid") -> Decimal:
    """Parse a finite, non-negative value without accepting rounding loss."""
    if isinstance(value, bool) or value is None:
        raise OrderValidationError(reason)
    try:
        amount = Decimal(str(value))
        normalized = amount.quantize(MONEY_QUANTUM)
    except (InvalidOperation, ValueError, TypeError):
        raise OrderValidationError(reason) from None
    if not amount.is_finite() or amount < 0 or amount != normalized:
        raise OrderValidationError(reason)
    return normalized


def _require_money(
    container: Mapping[str, Any],
    field: str,
    expected: Decimal,
    reason: str,
) -> None:
    if field not in container:
        raise OrderValidationError(reason)
    if parse_money(container[field]) != expected:
        raise OrderValidationError(reason)


def validate_canonical_order(
    order: Any,
    *,
    expected_order_id: str,
    products: Mapping[str, tuple[str, Any]],
) -> CanonicalOrder:
    """Validate all payment-authorizing fields from a Shopier Order object.

    ``products`` maps Shopier product IDs to ``(plan_name, exact_price)``.
    The initial policy intentionally rejects discounts, shipping, additional
    line items and quantities other than one.
    """
    if not isinstance(order, dict):
        raise OrderValidationError("api_payload_invalid")

    order_id = str(order.get("id") or "").strip()
    if not order_id or order_id != str(expected_order_id):
        raise OrderValidationError("api_order_id_mismatch")
    if order.get("paymentStatus") != "paid":
        raise OrderValidationError("payment_not_paid")
    if order.get("currency") != "TRY":
        raise OrderValidationError("currency_mismatch")

    line_items = order.get("lineItems")
    if not isinstance(line_items, list) or not line_items:
        raise OrderValidationError("line_items_invalid")
    if len(line_items) != 1 or not isinstance(line_items[0], dict):
        raise OrderValidationError("unexpected_line_items")

    line_item = line_items[0]
    product_id = str(line_item.get("productId") or "").strip()
    product = products.get(product_id)
    if product is None:
        raise OrderValidationError("product_unknown")
    plan, configured_price = product
    expected_amount = parse_money(configured_price, reason="configured_price_invalid")

    quantity = line_item.get("quantity")
    if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity != 1:
        raise OrderValidationError("quantity_mismatch")

    _require_money(line_item, "price", expected_amount, "line_price_mismatch")
    _require_money(line_item, "total", expected_amount, "line_total_mismatch")

    totals = order.get("totals")
    if not isinstance(totals, dict):
        raise OrderValidationError("totals_invalid")
    _require_money(totals, "subtotal", expected_amount, "subtotal_mismatch")
    _require_money(totals, "shipping", Decimal("0.00"), "shipping_not_allowed")
    _require_money(totals, "discount", Decimal("0.00"), "discount_not_allowed")
    _require_money(totals, "total", expected_amount, "order_total_mismatch")

    discounts = order.get("discounts")
    if discounts not in (None, []):
        raise OrderValidationError("discount_not_allowed")

    token = None
    token_error = None
    try:
        token = extract_single_token(order.get("note"))
    except OrderValidationError as exc:
        token_error = exc.reason

    return CanonicalOrder(
        order_id=order_id,
        plan=plan,
        product_id=product_id,
        amount=expected_amount,
        amount_minor=int(expected_amount * 100),
        token=token,
        token_error=token_error,
    )
