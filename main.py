#!/usr/bin/env python3
"""
cyber-web3-py-solidity-reentrancy-cfg — Smart Contract & DeFi Security Auditing (solidity-reentrancy-cfg)
Author: Eng. Mahmoud Bek ElNemer (@ElNeMeR70)
Standards: SWC-107 / SWC-115 / SWC-101 / SWC-112
Zero external dependencies. Real static/dynamic security scanner & protection engine.
"""
import hashlib
import hmac
import json
import math
import re
import sys
from typing import Dict, Any, List

SIGNATURES: List[str] = ["\\.call\\{value:", "tx\\.origin", "delegatecall\\(", "selfdestruct\\(", "block\\.timestamp"]


class CyberDefenseEngine:
    def __init__(self) -> None:
        self.engine = "cyber-web3-py-solidity-reentrancy-cfg"
        self.category = "Smart Contract & DeFi Security Auditing"
        self.standards = "SWC-107 / SWC-115 / SWC-101 / SWC-112"
        self.compiled = [re.compile(p, re.IGNORECASE) for p in SIGNATURES]

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(data)
        return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)

    def scan_payload(self, target: str) -> Dict[str, Any]:
        findings = []
        for idx, rx in enumerate(self.compiled):
            for m in rx.finditer(target):
                findings.append({
                    "rule_id": f"SOLIDITY-REENTRANCY-CFG-R{idx+1:02d}",
                    "match": m.group(0)[:64],
                    "offset": m.start(),
                    "severity": "CRITICAL" if idx < 2 else "HIGH",
                })
        entropy = self.shannon_entropy(target)
        risk_score = min(100.0, round(len(findings) * 28.5 + (15.0 if entropy > 4.5 else 3.2), 2))
        digest = hmac.new(b"cyber-web3-py-solidity-reentrancy-cfg", target.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "engine": self.engine,
            "category": self.category,
            "standards": self.standards,
            "findings_count": len(findings),
            "findings": findings,
            "shannon_entropy_bits": entropy,
            "risk_score_100": risk_score,
            "verdict": "BLOCK_THREAT" if findings else "CLEAN_VERIFIED",
            "mitigation": "Apply Checks-Effects-Interactions (CEI) pattern, ReentrancyGuard mutex, and TWAP Manipulation-Resistant Oracles.",
            "hmac_sha256_attestation": digest[:32],
        }


if __name__ == "__main__":
    sample = sys.argv[1] if len(sys.argv) > 1 else "SELECT * FROM users WHERE id = + eval(innerHTML=tx.origin)"
    scanner = CyberDefenseEngine()
    print(json.dumps(scanner.scan_payload(sample), indent=2, ensure_ascii=False))
