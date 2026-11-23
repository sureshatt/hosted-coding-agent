"""Invoice totals."""
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal


@dataclass
class Line:
    description: str
    unit_price: Decimal
    quantity: int


def subtotal(lines: list[Line]) -> Decimal:
    return sum((line.unit_price for line in lines), Decimal("0"))


def total(lines: list[Line], tax_rate: Decimal) -> Decimal:
    gross = subtotal(lines) * (Decimal("1") + tax_rate)
    return gross.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
