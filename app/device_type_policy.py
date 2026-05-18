"""
Cihaz türü (router / switch / layer-3 switch) — denetim kapsamını buna göre daraltır.
"""

from __future__ import annotations

import re

from app.models import Finding

DEVICE_TYPE_LABELS_TR: dict[str, str] = {
    "unknown": "Belirsiz — tüm kurallar",
    "router": "Router",
    "switch": "Switch (L2)",
    "layer3_switch": "Switch (L3)",
}

SKIP_RULES_BY_DEVICE_TYPE: dict[str, frozenset[str]] = {
    "unknown": frozenset(),
    "switch": frozenset(),
    "layer3_switch": frozenset(),
    "router": frozenset(
        {
            "R001",
            "R003",
            "R025",
            "R035",
            "R036",
            "R037",
            "R044",
            "R045",
            "R029",
            "R030",
            "R034",
        }
    ),
}


def infer_device_type(text: str) -> str:
    """Konfigürasyondan router / switch / layer3_switch tahmini (önceki _detect_device_role mantığı)."""
    has_router_keywords = bool(
        re.search(
            r"^\s*(router\s+(ospf|bgp|eigrp|rip)|ip\s+route\s+\S+)",
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
    )
    has_switch_keywords = bool(
        re.search(
            r"^\s*(switchport\s+|spanning-tree\s+|vlan\s+\d+)",
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
    )
    if has_router_keywords and not has_switch_keywords:
        return "router"
    if has_switch_keywords and not has_router_keywords:
        return "switch"
    if has_switch_keywords and has_router_keywords:
        return "layer3_switch"
    return "unknown"


def filter_findings_by_device_type(findings: list[Finding], device_type: str) -> list[Finding]:
    skip = SKIP_RULES_BY_DEVICE_TYPE.get(device_type)
    if not skip:
        return findings
    return [f for f in findings if f.rule_id not in skip]



DEVICE_ROLE_LABELS = {
    "unknown": "Belirsiz",
    "router": "WAN / Edge",
    "core": "Omurga (Core / Distribution)",
    "access": "Kenar (Access / Departman)",
}

SKIP_RULES_BY_ROLE = {
    "access": {
        "R005", # BGP neighbor şifresiz
        "R006", # OSPF alan kimlik doğrulaması yok
        "R048", # CoPP tanımlı değil
        "R052", # uRPF eksik
        "R056", # BGP neighbor şifresiz (tekrar)
        "R066", # BGP weak password
        "R067", # OSPF weak password
        "R068", # ISAKMP VPN weak password
    },
    "core": set(),
    "router": set(),
    "unknown": set()
}

def infer_device_role(text: str, device_type: str) -> str:
    """
    Konfigürasyon içeriğinden cihazın rolünü (Core vs Access) otomatik algılar.
    L3 bir switch'in backbone rolünde mi, yoksa yalnızca edge routing mi yaptığını tespit eder.
    """
    if device_type == "router":
        return "router"
    
    has_core_keywords = bool(
        re.search(
            r"^\s*(router\s+(bgp|ospf|isis|eigrp)|standby\s+\d+\s+ip|vrrp\s+\d+\s+ip|glbp\s+\d+\s+ip)",
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
    )
    
    if has_core_keywords:
        return "core"
        
    if device_type == "switch":
        return "access"
        
    return "access"

def filter_findings_by_device_role(findings: list[Finding], device_role: str) -> list[Finding]:
    skip = SKIP_RULES_BY_ROLE.get(device_role, set())
    if not skip:
        return findings
    return [f for f in findings if f.rule_id not in skip]
