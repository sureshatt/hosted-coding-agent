from decimal import Decimal

from invoice.totals import Line, subtotal, total

LINES = [Line("widget", Decimal("10.00"), 2), Line("gadget", Decimal("5.50"), 1)]


def test_subtotal_counts_quantity():
    assert subtotal(LINES) == Decimal("25.50")


def test_total_adds_tax_and_rounds():
    assert total(LINES, Decimal("0.10")) == Decimal("28.05")


def test_empty_invoice():
    assert total([], Decimal("0.10")) == Decimal("0.00")
