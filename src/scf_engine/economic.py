from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def _decimal(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return Decimal(0)


def value_forensics(case: dict[str, Any], valuations: dict[str, Any]) -> dict[str, Any]:
    """Value already-observed flows; never infer prices from the trace."""
    accounts: dict[str, Decimal] = {}
    token_breakdown: list[dict[str, Any]] = []
    for flow in case.get("execution", {}).get("erc20_flows", []):
        address = str(flow["address"])
        valuation = valuations.get(address) or valuations.get(address.lower())
        if valuation is None:
            continue
        price = _decimal(valuation.get("usd_per_raw_unit", 0))
        incoming = _decimal(flow.get("incoming", 0)) * price
        outgoing = _decimal(flow.get("outgoing", 0)) * price
        accounts[address] = accounts.get(address, Decimal(0)) + incoming - outgoing
        token_breakdown.append({
            "address": address,
            "incoming_usd": str(incoming),
            "outgoing_usd": str(outgoing),
            "net_usd": str(incoming - outgoing),
            "valuation_evidence": valuation.get("evidence"),
        })
    native_price = _decimal(valuations.get("NATIVE", {}).get("usd_per_raw_unit", 0))
    gas_cost = _decimal(case.get("transaction", {}).get("gas_used", 0))
    gas_price = _decimal(case.get("transaction", {}).get("effective_gas_price", 0))
    native_gas_usd = gas_cost * gas_price * native_price
    return {
        "status": "VALUED_FLOW" if token_breakdown or native_price else "NO_VALUATION",
        "token_breakdown": token_breakdown,
        "account_net_usd": [{"address": k, "net_usd": str(v)} for k, v in sorted(accounts.items())],
        "gas_cost_usd": str(native_gas_usd),
        "profit_claim": None,
        "limitations": [
            "Valuations are operator-supplied and must include evidence.",
            "Valued flow is not realized profit or loss without complete balance, price-impact and fee evidence.",
        ],
    }
