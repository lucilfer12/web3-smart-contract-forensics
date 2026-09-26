from __future__ import annotations

import re
from typing import Iterable

from .base import Detector
from ..models import Evidence, Finding, SourceUnit, ContractModel, FunctionModel, SourceLocation


def ev(fn: FunctionModel, rule: str, reason: str, confidence: float, snippet: str | None = None) -> Evidence:
    return Evidence(
        source=fn.location,
        snippet=(snippet or fn.body_text[:360]).strip(),
        reason=reason,
        rule=rule,
        confidence=confidence,
    )


def ev_at(fn: FunctionModel, rule: str, reason: str, confidence: float, loc: SourceLocation, snippet: str) -> Evidence:
    return Evidence(source=loc, snippet=snippet[:360].strip(), reason=reason, rule=rule, confidence=confidence)


class ReentrancyDetector(Detector):
    rule_id = "SCF-REENTRANCY-001"
    title = "External interaction precedes state mutation"
    severity = "High"
    cwe = "CWE-841"
    swc = "SWC-107"
    tags = ("reentrancy", "external-call", "state-change")

    def run(self, unit: SourceUnit, contract: ContractModel, function: FunctionModel) -> Iterable[Finding]:
        if function.mutability in {"view", "pure"} or not function.calls or not function.writes:
            return []
        if any(m.lower().startswith("nonreentrant") for m in function.modifiers):
            return []
        external = [c for c in function.calls if c.external]
        if not external:
            return []
        first_call = min(external, key=lambda c: (c.location.line, c.location.column))
        confidence = 0.78 + (0.10 if first_call.low_level else 0.0) + (0.05 if first_call.value_transfer else 0.0)
        return [self.make_finding(
            function=function,
            description="The function performs an external interaction and also mutates contract state. Without an established reentrancy guard, the ordering is a review candidate for checks-effects-interactions violations.",
            recommendation="Confirm whether the external call can re-enter this contract; apply a proven guard and/or move state effects before the interaction where the protocol semantics permit.",
            evidence=[ev_at(function, self.rule_id, "External call occurs in a state-changing function.", min(confidence, .95), first_call.location, first_call.text)],
            confidence=min(confidence, .93),
        )]


class TxOriginDetector(Detector):
    rule_id = "SCF-AUTH-001"
    title = "tx.origin used in authorization-sensitive code"
    severity = "High"
    cwe = "CWE-477"
    swc = "SWC-115"
    tags = ("authentication", "tx.origin")

    def run(self, unit, contract, function):
        if not function.uses_tx_origin:
            return []
        auth_context = bool(re.search(r"\b(require|assert|if)\s*\([^;]*tx\.origin", function.body_text, re.S))
        if not auth_context and "tx.origin" not in function.body_text:
            return []
        conf = 0.92 if auth_context else 0.72
        return [self.make_finding(
            function=function,
            description="tx.origin participates in control flow. Authorization built on transaction origin can be confused by intermediate contracts and should be reviewed as a phishing/call-chain risk.",
            recommendation="Use msg.sender for caller identity and explicit capability checks; reserve tx.origin for narrowly justified use cases that are not authorization decisions.",
            evidence=[ev(function, self.rule_id, "tx.origin is referenced in the function body.", conf)],
            confidence=conf,
        )]


class UncheckedCallDetector(Detector):
    rule_id = "SCF-EXTERNAL-001"
    title = "Low-level call result may be unchecked"
    severity = "Medium"
    cwe = "CWE-252"
    swc = "SWC-104"
    tags = ("unchecked-return", "low-level-call")

    def run(self, unit, contract, function):
        results = []
        for call in function.calls:
            if not call.low_level:
                continue
            body = function.body_text
            checked = bool(re.search(r"(require|assert)\s*\([^;]*\b(ok|success|sent|result)\b", body, re.S)) or bool(re.search(r"if\s*\(\s*!\s*\b(ok|success|sent|result)\b", body))
            if checked:
                continue
            conf = 0.86 if call.kind == "external" else 0.74
            results.append(self.make_finding(
                function=function,
                description="A low-level external interaction is present without an obvious check of its boolean result in the enclosing function.",
                recommendation="Capture and validate the return value according to the called operation's semantics, or use a typed interface/helper that enforces the expected failure behavior.",
                evidence=[ev_at(function, self.rule_id, "Low-level call result lacks an obvious local check.", conf, call.location, call.text)],
                confidence=conf,
            ))
        return results


class DelegatecallDetector(Detector):
    rule_id = "SCF-UPGRADE-001"
    title = "delegatecall reaches a potentially dynamic target"
    severity = "High"
    cwe = "CWE-829"
    swc = "SWC-112"
    tags = ("delegatecall", "proxy", "code-execution")

    def run(self, unit, contract, function):
        out = []
        for call in function.calls:
            if call.callee.rsplit(".", 1)[-1] != "delegatecall":
                continue
            raw = function.body_text
            dynamic = bool(re.search(r"\b(address\s+\w+|target|implementation|module|plugin)\b", raw, re.I))
            conf = 0.84 if dynamic else 0.68
            out.append(self.make_finding(
                function=function,
                description="delegatecall executes code in the caller's storage context. The analyzed call site should be constrained by an explicit trusted implementation policy.",
                recommendation="Restrict delegatecall targets to trusted implementations, validate upgrade authority, and test storage/layout compatibility across upgrade paths.",
                evidence=[ev_at(function, self.rule_id, "delegatecall call site detected.", conf, call.location, call.text)],
                confidence=conf,
            ))
        return out


class DestructionDetector(Detector):
    rule_id = "SCF-DESTRUCT-001"
    title = "Contract destruction primitive is reachable"
    severity = "High"
    cwe = "CWE-284"
    swc = "SWC-106"
    tags = ("selfdestruct", "privilege")

    def run(self, unit, contract, function):
        if "selfdestruct(" not in function.body_text and "suicide(" not in function.body_text:
            return []
        guarded = bool(function.modifiers) or bool(re.search(r"require\s*\([^;]*(owner|admin|authorized)", function.body_text, re.I | re.S))
        conf = 0.91 if not guarded else 0.72
        return [self.make_finding(
            function=function,
            description="The function contains a contract-destruction primitive. Reachability and authorization determine whether this is an exploitable control-plane risk.",
            recommendation="Verify explicit, least-privilege authorization and emergency-governance assumptions; avoid exposing destruction through untrusted control flow.",
            evidence=[ev(function, self.rule_id, "Contract destruction primitive appears in the function body.", conf)],
            confidence=conf,
        )]


class TimestampRandomnessDetector(Detector):
    rule_id = "SCF-RANDOM-001"
    title = "Block timestamp participates in randomness or sensitive branching"
    severity = "Medium"
    cwe = "CWE-330"
    swc = "SWC-116"
    tags = ("timestamp", "randomness", "miner-influence")

    def run(self, unit, contract, function):
        if not function.uses_timestamp:
            return []
        body = function.body_text
        randomish = bool(re.search(r"keccak256\s*\([^)]*timestamp|random|seed|lottery|winner|nonce", body, re.I | re.S))
        sensitive = bool(re.search(r"require\s*\(|\bif\s*\(|==|<|>|%", body))
        if not (randomish or sensitive):
            return []
        conf = 0.88 if randomish else 0.70
        return [self.make_finding(
            function=function,
            description="block.timestamp influences program behavior and may be unsuitable as an unpredictable source when outcomes are economically sensitive.",
            recommendation="Use a protocol-appropriate randomness source or commit-reveal mechanism for unpredictability; treat timestamp only as a coarse time signal.",
            evidence=[ev(function, self.rule_id, "Timestamp participates in sensitive control flow or random-looking computation.", conf)],
            confidence=conf,
        )]


class BlockhashRandomnessDetector(Detector):
    rule_id = "SCF-RANDOM-002"
    title = "Recent blockhash used as randomness"
    severity = "Medium"
    cwe = "CWE-330"
    swc = "SWC-120"
    tags = ("blockhash", "randomness")

    def run(self, unit, contract, function):
        if not function.uses_blockhash:
            return []
        body = function.body_text
        conf = 0.90 if re.search(r"random|seed|winner|lottery|keccak256", body, re.I) else 0.70
        return [self.make_finding(
            function=function,
            description="blockhash() is used and may influence an unpredictable or economically sensitive result. Recent block hashes have known availability and bias constraints.",
            recommendation="Use a protocol-designed randomness construction with explicit adversarial assumptions instead of treating blockhash as a secure oracle.",
            evidence=[ev(function, self.rule_id, "blockhash() appears in the function body.", conf)],
            confidence=conf,
        )]


class AccessControlDetector(Detector):
    rule_id = "SCF-ACCESS-001"
    title = "State-changing privileged-looking function lacks obvious authorization"
    severity = "High"
    cwe = "CWE-862"
    swc = "SWC-105"
    tags = ("access-control", "privilege", "state-change")

    SENSITIVE = re.compile(r"(upgrade|initialize|set[A-Z]|withdraw|rescue|mint|burn|pause|unpause|grant|revoke|changeOwner|transferOwnership|sweep|execute)")

    def run(self, unit, contract, function):
        if function.visibility not in {"public", "external"} or not function.writes:
            return []
        if not self.SENSITIVE.search(function.name):
            return []
        user_scoped = bool(re.search(r"\bmsg\.sender\b", function.body_text)) and bool(re.search(r"\b(balance|balances|shares|deposits|credits)\s*\[\s*msg\.sender", function.body_text))
        if user_scoped and function.name.lower().startswith(("withdraw", "burn")):
            return []
        guarded_by_modifier = bool(function.modifiers)
        guarded_in_body = bool(re.search(r"\b(msg\.sender\s*==|owner\s*==|admin\s*==|hasRole\s*\()", function.body_text, re.I))
        if guarded_by_modifier or guarded_in_body:
            return []
        return [self.make_finding(
            function=function,
            description="A publicly reachable, state-changing function has a privilege-sensitive name but no obvious modifier or in-body authorization predicate was detected.",
            recommendation="Define the intended authority explicitly, enforce it before state mutation, and add invariant tests for unauthorized callers.",
            evidence=[ev(function, self.rule_id, "Sensitive public/external function mutates state without an obvious authorization check.", 0.80)],
            confidence=0.80,
        )]


DEFAULT_DETECTORS = [
    ReentrancyDetector(),
    TxOriginDetector(),
    UncheckedCallDetector(),
    DelegatecallDetector(),
    DestructionDetector(),
    TimestampRandomnessDetector(),
    BlockhashRandomnessDetector(),
    AccessControlDetector(),
]


class UncheckedTokenTransferDetector(Detector):
    rule_id = "SCF-TOKEN-001"
    title = "ERC-20 transfer result is not obviously validated"
    severity = "Medium"
    cwe = "CWE-252"
    swc = "SWC-104"
    tags = ("erc20", "unchecked-return")

    def run(self, unit, contract, function):
        hits = re.findall(r"\b\w+\.(?:transfer|transferFrom)\s*\([^;]+\)", function.body_text)
        if not hits:
            return []
        if "SafeERC20" in function.body_text or re.search(r"require\s*\([^;]*(?:transfer|transferFrom)", function.body_text, re.S):
            return []
        return [self.make_finding(
            function=function,
            description="A token transfer call is present without an obvious SafeERC20 wrapper or local success check.",
            recommendation="Use SafeERC20 or explicitly validate the token operation's return semantics before relying on the transfer.",
            evidence=[ev(function, self.rule_id, "ERC-20 transfer-like call lacks an obvious local validation path.", 0.78, hits[0])],
            confidence=0.78,
        )]


class OracleManipulationDetector(Detector):
    rule_id = "SCF-ECONOMIC-001"
    title = "Spot AMM state appears to influence an economic decision"
    severity = "High"
    cwe = "CWE-682"
    tags = ("oracle", "amm", "economic-security")

    ORACLE = re.compile(r"(?:\.getReserves\s*\(|\.slot0\s*\(|\breserves?\b)", re.I)
    SENSITIVE = re.compile(r"\b(?:price|quote|borrow|liquidat|collateral|mint|redeem|swap|exchange|health)\w*\b", re.I)

    def run(self, unit, contract, function):
        body = function.body_text
        if not self.ORACLE.search(body) or not self.SENSITIVE.search(body):
            return []
        if re.search(r"(?:TWAP|Chainlink|AggregatorV3|oracle|time[-_ ]weighted)", body, re.I):
            return []
        return [self.make_finding(
            function=function,
            description="A spot-market state source appears in an economically sensitive path without an obvious independent oracle or time-weighted construction.",
            recommendation="Model manipulation at the transaction level and use a protocol-appropriate oracle with explicit staleness, deviation, and source-diversity checks.",
            evidence=[ev(function, self.rule_id, "Spot AMM state and an economic-sensitive operation occur in the same function.", 0.75)],
            confidence=0.75,
        )]


class SignatureReplayDetector(Detector):
    rule_id = "SCF-AUTH-002"
    title = "Signature-based authorization lacks an obvious replay boundary"
    severity = "High"
    cwe = "CWE-294"
    tags = ("signature", "replay", "eip-712")

    def run(self, unit, contract, function):
        body = function.body_text
        signature_flow = bool(re.search(r"ecrecover|signature|\bv\b.*\br\b.*\bs\b|permit|metaTx|execute", body, re.I))
        if not signature_flow:
            return []
        has_nonce = bool(re.search(r"\bnonce\w*\b", body, re.I))
        has_deadline = bool(re.search(r"\bdeadline\w*\b|block\.timestamp\s*[<=>]", body, re.I))
        has_domain = bool(re.search(r"chainId|DOMAIN_SEPARATOR|EIP712", body, re.I))
        if has_nonce and (has_deadline or has_domain):
            return []
        conf = 0.86 if not has_nonce else 0.72
        return [self.make_finding(
            function=function,
            description="Signature-based control flow was detected without an obvious combination of nonce and expiry/domain separation protections.",
            recommendation="Bind signed intent to a consumed nonce, explicit expiry, and domain/chain context appropriate to the protocol.",
            evidence=[ev(function, self.rule_id, "Signature authorization path lacks an obvious replay boundary.", conf)],
            confidence=conf,
        )]


class InitializerDetector(Detector):
    rule_id = "SCF-UPGRADE-002"
    title = "Initializer-like function lacks an obvious one-time guard"
    severity = "High"
    cwe = "CWE-665"
    tags = ("proxy", "initializer", "upgrade")

    def run(self, unit, contract, function):
        if not re.match(r"^(?:initialize|init|postInitialize)$", function.name, re.I):
            return []
        if function.visibility not in {"public", "external"}:
            return []
        body = function.body_text
        guarded = any("initializer" in m.lower() for m in function.modifiers) or bool(re.search(r"_initialized|initialized\s*\|?\s*|onlyInitializing|_disableInitializers", body, re.I))
        if guarded:
            return []
        return [self.make_finding(
            function=function,
            description="An externally reachable initializer-like function has no obvious one-time initialization guard.",
            recommendation="Use an audited initializer pattern, protect initialization exactly once, and disable implementation initialization where proxy architecture requires it.",
            evidence=[ev(function, self.rule_id, "Initializer-like entry point lacks an obvious initialization guard.", 0.84)],
            confidence=0.84,
        )]


class LoopDoSDetector(Detector):
    rule_id = "SCF-DOS-001"
    title = "Loop may scale with attacker-controlled collection size"
    severity = "Medium"
    cwe = "CWE-400"
    swc = "SWC-128"
    tags = ("dos", "loop", "gas")

    def run(self, unit, contract, function):
        if function.loops == 0:
            return []
        body = function.body_text
        dynamic = bool(re.search(r"for\s*\([^;]*;[^;]*(?:\.length|length\s*[<=>])", body, re.S))
        if not dynamic:
            return []
        confidence = 0.78 if any(c.external for c in function.calls) else 0.67
        return [self.make_finding(
            function=function,
            description="A loop appears to depend on a dynamically sized collection; gas cost may grow with attacker-influenced state.",
            recommendation="Bound iteration, paginate work, use pull-based accounting, or otherwise make gas growth independent of untrusted collection size.",
            evidence=[ev(function, self.rule_id, "Dynamic loop bound detected in a state-changing function.", confidence)],
            confidence=confidence,
        )]


DEFAULT_DETECTORS = [
    ReentrancyDetector(), TxOriginDetector(), UncheckedCallDetector(),
    DelegatecallDetector(), DestructionDetector(), TimestampRandomnessDetector(),
    BlockhashRandomnessDetector(), AccessControlDetector(), UncheckedTokenTransferDetector(),
    OracleManipulationDetector(), SignatureReplayDetector(), InitializerDetector(), LoopDoSDetector(),
]
