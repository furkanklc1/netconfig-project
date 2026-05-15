import re

from app.models import Finding


_IPV4_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b")


_SECRET_PATTERNS: list[dict] = [
    {
        "rule_id": "R062",
        "regex": re.compile(
            r"\bpassword\s+7\s+(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "Cisco Type 7 password tespit edildi (saniyeler içinde decode edilebilir).",
    },
    {
        "rule_id": "R063",
        "regex": re.compile(
            r"\bpassword\s+0\s+(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "Type 0 (cleartext) password tespit edildi.",
    },
    {
        "rule_id": "R064",
        "regex": re.compile(
            r"\btacacs(?:-server)?\b[^\n]*?\bkey\s+(?:0\s+)?(?!7\b)(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "TACACS+ key cleartext olarak tanımlanmış.",
    },
    {
        "rule_id": "R065",
        "regex": re.compile(
            r"\bradius(?:-server)?\b[^\n]*?\bkey\s+(?:0\s+)?(?!7\b)(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "RADIUS key cleartext olarak tanımlanmış.",
    },
    {
        "rule_id": "R066",
        "regex": re.compile(
            r"\bneighbor\s+\S+\s+password\s+(?:0\s+)?(?!7\b)(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "BGP neighbor password cleartext olarak tanımlanmış.",
    },
    {
        "rule_id": "R067",
        "regex": re.compile(
            r"\bip\s+ospf\s+(?:message-digest-key\s+\d+\s+md5|authentication-key)\s+(?:0\s+)?(?!7\b)(?P<secret>\S+)",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "OSPF MD5 / authentication-key cleartext olarak tanımlanmış.",
    },
    {
        "rule_id": "R068",
        "regex": re.compile(
            r"\bcrypto\s+isakmp\s+key\s+(?:0\s+)?(?!6\b)(?P<secret>\S+)\s+address\s+\S+",
            flags=re.IGNORECASE,
        ),
        "severity": "critical",
        "category": "security",
        "message": "ISAKMP/IPsec pre-shared key cleartext olarak tanımlanmış.",
    },
]


_GENERIC_MASK_PATTERNS: list[re.Pattern] = [p["regex"] for p in _SECRET_PATTERNS]


def _mask_secret_in(match: re.Match) -> str:
    full = match.group(0)
    secret_start = match.start("secret") - match.start(0)
    secret_end = match.end("secret") - match.start(0)
    secret = match.group("secret")
    masked = "*" * max(8, len(secret))
    return full[:secret_start] + masked + full[secret_end:]


def _mask_ipv4(text: str) -> str:
    return _IPV4_REGEX.sub(r"\1.x", text)


def mask_credentials_in_line(line: str, *, mask_ipv4: bool = False) -> str:
    masked = line
    # Kullanıcı talebi: Şifreler maskelenmeyecek (config'de nasılsa öyle görünecek).
    # for pattern in _GENERIC_MASK_PATTERNS:
    #     masked = pattern.sub(_mask_secret_in, masked)
    if mask_ipv4:
        masked = _mask_ipv4(masked)
    return masked


def scan_secrets(config_text: str) -> list[Finding]:
    findings: list[Finding] = []
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue
        for pattern_def in _SECRET_PATTERNS:
            regex: re.Pattern = pattern_def["regex"]
            match = regex.search(line)
            if not match:
                continue
            masked = mask_credentials_in_line(line, mask_ipv4=True)
            findings.append(
                Finding(
                    rule_id=pattern_def["rule_id"],
                    severity=pattern_def["severity"],
                    message=pattern_def["message"],
                    context=masked,
                    category=pattern_def["category"],
                )
            )
    return findings
