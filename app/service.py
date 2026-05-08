import difflib
import re

from app.ai_commentary import format_report
from app.parser import parse_cisco_ios_config
from app.rules import run_rules


_IOS_MARKER_PATTERNS: list[str] = [
    r"^\s*hostname\s+\S+",
    r"^\s*interface\s+\S+",
    r"^\s*line\s+(console|con|vty|aux)\b",
    r"^\s*router\s+(ospf|bgp|eigrp|rip)\b",
    r"^\s*ip\s+route\s+\S+",
    r"^\s*vlan\s+\d+",
    r"^\s*access-list\s+\S+",
    r"^\s*spanning-tree\s+\S+",
    r"^\s*service\s+(timestamps|password-encryption|finger|pad|tcp-keepalives)",
    r"^\s*enable\s+(secret|password)\s+",
    r"^\s*ip\s+http\s+(server|secure-server)",
    r"^\s*aaa\s+new-model",
    r"^\s*snmp-server\s+\S+",
    r"^\s*crypto\s+(key|isakmp|ipsec|pki)",
    r"^\s*boot\s+system\s+\S+",
    r"^\s*version\s+\d+\.\d+",
    r"^\s*switchport\s+(mode|access|trunk)",
    r"^\s*ntp\s+server\s+\S+",
    r"^\s*banner\s+motd\b",
    r"^\s*ip\s+ssh\s+version\s+\d+",
    r"^\s*logging\s+(host|buffered|trap)",
    r"^\s*control-plane\s*$",
]


def is_cisco_ios_config(text: str) -> bool:
    if not text or not text.strip():
        return False
    matched = 0
    for pattern in _IOS_MARKER_PATTERNS:
        if re.search(pattern, text, flags=re.MULTILINE | re.IGNORECASE):
            matched += 1
            if matched >= 3:
                return True
    return False


def validate_config_text(text: str) -> tuple[bool, str]:
    if not text or not text.strip():
        return False, "Dosya boş görünüyor."
    info = detect_device_info(text)
    vendor = info.get("vendor", "Unknown")
    if vendor not in ("Unknown", "Cisco IOS"):
        return False, (
            f"Yüklenen dosya {vendor} konfigürasyonu olarak algılandı. "
            "NetConfig AI şu anda yalnızca Cisco IOS / IOS XE destekler."
        )
    if is_cisco_ios_config(text):
        return True, ""
    return False, (
        "Yüklenen dosya geçerli bir Cisco IOS konfigürasyonu olarak görünmüyor. "
        "Lütfen `show running-config` çıktısı içeren bir .txt veya .cfg dosyası yükleyin."
    )


def _extract_hostname(text: str) -> str | None:
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^hostname\s+(\S+)$", line, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


_PLATFORM_PATTERNS: list[tuple[str, str]] = [
    (r"isr4\d{3}", "Cisco ISR 4000"),
    (r"asr1\d{3}", "Cisco ASR 1000"),
    (r"asr9\d{3}", "Cisco ASR 9000"),
    (r"cat9k|c9300|c9400|c9500|c9600", "Cisco Catalyst 9000"),
    (r"c2900|c2911|c2921|c2951", "Cisco 2900 ISR"),
    (r"c3900|c3925|c3945", "Cisco 3900 ISR"),
    (r"c1900|c1921|c1941", "Cisco 1900 ISR"),
    (r"c1841|c1861", "Cisco 1800 ISR"),
    (r"c800|c881|c891", "Cisco 800 ISR"),
    (r"c2960", "Cisco Catalyst 2960"),
    (r"c3560", "Cisco Catalyst 3560"),
    (r"c3750", "Cisco Catalyst 3750"),
    (r"c3850", "Cisco Catalyst 3850"),
    (r"c4500|c4503|c4506|c4507|c4510", "Cisco Catalyst 4500"),
    (r"c6500|c6504|c6506|c6509|c6513", "Cisco Catalyst 6500"),
    (r"nxos|n3k|n5k|n7k|n9k", "Cisco Nexus"),
    (r"csr1000v|vios|cml", "Cisco Virtual"),
]


def _platform_from_boot_image(image_name: str) -> str | None:
    name_lower = image_name.lower()
    for pattern, label in _PLATFORM_PATTERNS:
        if re.search(pattern, name_lower):
            return label
    return None


_VENDOR_PATTERNS: list[tuple[str, str]] = [
    (
        "Juniper",
        r"^\s*set\s+(system|interfaces|protocols|routing-options|firewall|chassis)\s+\S+",
    ),
    (
        "Huawei",
        r"^\s*sysname\s+\S+|^\s*display\s+current-configuration|^\s*super\s+password\s+",
    ),
    (
        "Cisco NX-OS",
        r"^\s*feature\s+(ospf|bgp|eigrp|pim|hsrp|lacp|interface-vlan|vpc|telnet|ssh)"
        r"|^\s*role\s+name\s+\S+"
        r"|^\s*vpc\s+domain\s+\d+"
        r"|^\s*system\s+jumbomtu\s+\d+"
        r"|^\s*boot\s+nxos\s+(bootflash:|nxos\.)"
        r"|^\s*username\s+\S+\s+password\s+\S+\s+role\s+\S+",
    ),
    (
        "HPE Aruba",
        r"^\s*!\s*Version\s+ArubaOS"
        r"|^\s*!\s*ArubaOS"
        r"|^\s*!\s*Aruba(?:OS|-CX|\s)"
        r"|^\s*!\s*HPE\s+"
        r"|^\s*;\s*Version\s+\""
        r"|^\s*Running\s+configuration:\s*$"
        r"|^\s*password\s+(manager|operator)\s+user-name"
        r"|^\s*module\s+\d+\s+type\s+\S+"
        r"|^\s*include-credentials\s*$"
        r"|^\s*aaa\s+server-group\s+\""
        r"|^\s*wlan\s+ssid-profile\s+"
        r"|^\s*ap\s+system-profile\s+"
        r"|^\s*user\s+\S+\s+group\s+\S+\s+password\s+ciphertext"
        r"|^\s*ssh\s+server\s+vrf\s+\S+"
        r"|^\s*vlan\s+access\s+\d+"
        r"|^\s*interface\s+\d+/\d+/\d+\s*$"
        r"|^\s*interface\s+lag\s+\d+"
        r"|^\s*untagged\s+vlan\s+\d+",
    ),
    (
        "Dell OS",
        r"^\s*system\s+identifier\s+\d+"
        r"|^\s*!\s*Dell\s+(EMC|OS|Force10|Networking)"
        r"|^\s*interface\s+ethernet\s*\d+/\d+/\d+"
        r"|^\s*username\s+\S+\s+password\s+\S+\s+role\s+sysadmin"
        r"|^\s*os10#\s*$",
    ),
    (
        "Arista EOS",
        r"^\s*!\s*device:\s+\S+"
        r"|^\s*!\s+Command:\s+show\s+running-config"
        r"|^\s*daemon\s+TerminAttr"
        r"|^\s*(no\s+)?aaa\s+root\s+(secret|disable)"
        r"|^\s*username\s+\S+\s+(privilege\s+\d+\s+)?role\s+\S+\s+secret"
        r"|^\s*transceiver\s+qsfp\s+default-mode"
        r"|^\s*event-handler\s+\S+"
        r"|^\s*event-monitor\s+\S+"
        r"|^\s*tap\s+aggregation"
        r"|^\s*management\s+api\s+http-commands"
        r"|^\s*queue-monitor\s+streaming"
        r"|^\s*mlag\s+configuration",
    ),
]


def detect_device_info(text: str) -> dict:
    info: dict = {
        "vendor": "Unknown",
        "platform": None,
        "os_version": None,
        "boot_image": None,
    }

    for vendor_label, pattern in _VENDOR_PATTERNS:
        if re.search(pattern, text, flags=re.MULTILINE | re.IGNORECASE):
            info["vendor"] = vendor_label
            break

    if info["vendor"] == "Unknown":
        has_cisco_ios_markers = re.search(
            r"^\s*(aaa\s+new-model"
            r"|service\s+(timestamps|password-encryption)"
            r"|line\s+(console|con|vty|aux)\s+\d+"
            r"|enable\s+secret\s+"
            r"|ip\s+http\s+server"
            r"|crypto\s+key\s+generate\s+rsa)",
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        has_hostname = re.search(
            r"^\s*hostname\s+\S+",
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        if has_cisco_ios_markers:
            info["vendor"] = "Cisco IOS"
        elif has_hostname:
            info["vendor"] = "Cisco IOS"

    version_match = re.search(
        r"^\s*version\s+(\d+\.\d+(?:\([^)]+\))?[a-zA-Z0-9.]*)",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if version_match:
        info["os_version"] = version_match.group(1)

    boot_match = re.search(
        r"^\s*boot\s+system\s+(?:flash:|bootflash:|disk\d+:|harddisk:)?([^\s]+)",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if boot_match:
        boot_image = boot_match.group(1)
        info["boot_image"] = boot_image
        platform = _platform_from_boot_image(boot_image)
        if platform:
            info["platform"] = platform

    if info["platform"] is None:
        if re.search(
            r"interface\s+(TwoGigabitEthernet|TwentyFiveGigE|HundredGigE|FortyGigabitEthernet)",
            text,
            flags=re.IGNORECASE,
        ):
            info["platform"] = "Cisco Catalyst 9000 / IOS XE"
        elif re.search(
            r"interface\s+Ethernet\d+/\d+",
            text,
            flags=re.IGNORECASE,
        ) and info["vendor"] == "Cisco NX-OS":
            info["platform"] = "Cisco Nexus"

    return info


def _detect_device_role(text: str) -> str:
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
        return "layer3-switch"
    return "unknown"


def audit_config_text(config_text: str) -> list[dict]:
    parsed = parse_cisco_ios_config(config_text)
    findings = run_rules(parsed)
    return format_report(findings)


def _finding_key(item: dict) -> tuple[str, str, str]:
    return (item["rule_id"], item["context"], item["message"])


def _extract_changed_lines(old_text: str, new_text: str) -> list[dict]:
    diff_lines = difflib.ndiff(old_text.splitlines(), new_text.splitlines())
    changed: list[dict] = []
    for line in diff_lines:
        if line.startswith("+ "):
            content = line[2:].strip()
            if content:
                changed.append({"source": "new", "prefix": "+", "line": content})
        elif line.startswith("- "):
            content = line[2:].strip()
            if content:
                changed.append({"source": "old", "prefix": "-", "line": content})
    unique_changed: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in changed:
        key = (line["source"], line["line"])
        if key not in seen:
            seen.add(key)
            unique_changed.append(line)
    return unique_changed


def _group_by_indent(raw_lines: list[str]) -> list[dict]:
    groups: list[dict] = []
    current: dict | None = None
    for raw in raw_lines:
        if not raw.strip():
            continue
        is_indented = raw.startswith((" ", "\t"))
        text = raw.strip()
        if is_indented and current is not None:
            if text not in current["children"]:
                current["children"].append(text)
        else:
            if current is not None:
                groups.append(current)
            current = {"parent": text, "children": []}
    if current is not None:
        groups.append(current)
    return groups


def _build_diff_groups(old_text: str, new_text: str) -> dict:
    old_lines_raw = [line for line in old_text.splitlines() if line.strip()]
    new_lines_raw = [line for line in new_text.splitlines() if line.strip()]
    old_lines = [line.strip() for line in old_lines_raw]
    new_lines = [line.strip() for line in new_lines_raw]
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)

    modified_pairs: list[dict] = []
    added_raw: list[str] = []
    removed_raw: list[str] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace":
            old_chunk = old_lines_raw[i1:i2]
            new_chunk = new_lines_raw[j1:j2]
            max_len = max(len(old_chunk), len(new_chunk))
            for idx in range(max_len):
                old_line = old_chunk[idx] if idx < len(old_chunk) else None
                new_line = new_chunk[idx] if idx < len(new_chunk) else None
                if old_line and new_line:
                    modified_pairs.append(
                        {
                            "old_line": old_line.strip(),
                            "new_line": new_line.strip(),
                        }
                    )
                elif old_line:
                    removed_raw.append(old_line)
                elif new_line:
                    added_raw.append(new_line)
        elif tag == "delete":
            removed_raw.extend(old_lines_raw[i1:i2])
        elif tag == "insert":
            added_raw.extend(new_lines_raw[j1:j2])

    return {
        "modified_pairs": modified_pairs,
        "added_groups": _group_by_indent(added_raw),
        "removed_groups": _group_by_indent(removed_raw),
    }


def audit_config_diff(old_text: str, new_text: str) -> dict:
    old_report = audit_config_text(old_text)
    new_report = audit_config_text(new_text)

    old_map = {_finding_key(item): item for item in old_report}
    new_map = {_finding_key(item): item for item in new_report}

    new_findings = [item for key, item in new_map.items() if key not in old_map]
    resolved_findings = [item for key, item in old_map.items() if key not in new_map]
    changed_lines = _extract_changed_lines(old_text, new_text)
    diff_groups = _build_diff_groups(old_text, new_text)
    changed_set = {line["line"].lower() for line in changed_lines}

    changed_line_findings = [
        item
        for item in new_report
        if item["context"].lower() in changed_set or any(
            token in item["context"].lower() for token in changed_set
        )
    ]

    old_hostname = _extract_hostname(old_text)
    new_hostname = _extract_hostname(new_text)
    old_role = _detect_device_role(old_text)
    new_role = _detect_device_role(new_text)
    old_device_info = detect_device_info(old_text)
    new_device_info = detect_device_info(new_text)

    mismatch_warnings: list[str] = []
    if old_hostname and new_hostname and old_hostname != new_hostname:
        mismatch_warnings.append(
            f"Yüklenen iki dosyanın hostname'i farklı: '{old_hostname}' ve "
            f"'{new_hostname}'. Diff sonucu yanıltıcı olabilir."
        )
    if old_role != "unknown" and new_role != "unknown" and old_role != new_role:
        mismatch_warnings.append(
            f"Cihaz rolleri farklı görünüyor (eski: {old_role}, yeni: {new_role}). "
            "Aynı cihazın iki versiyonunu karşılaştırdığınızdan emin olun."
        )
    if (
        old_device_info["vendor"] != "Unknown"
        and new_device_info["vendor"] != "Unknown"
        and old_device_info["vendor"] != new_device_info["vendor"]
    ):
        mismatch_warnings.append(
            f"Vendor farklı görünüyor (eski: {old_device_info['vendor']}, yeni: "
            f"{new_device_info['vendor']}). Aynı vendor için diff yapmanız önerilir."
        )
    if (
        old_device_info["platform"]
        and new_device_info["platform"]
        and old_device_info["platform"] != new_device_info["platform"]
    ):
        mismatch_warnings.append(
            f"Platform farklı görünüyor (eski: {old_device_info['platform']}, yeni: "
            f"{new_device_info['platform']})."
        )

    return {
        "changed_lines": changed_lines,
        "changed_line_count": len(changed_lines),
        "modified_pairs": diff_groups["modified_pairs"],
        "added_groups": diff_groups["added_groups"],
        "removed_groups": diff_groups["removed_groups"],
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "changed_line_findings": changed_line_findings,
        "old_hostname": old_hostname,
        "new_hostname": new_hostname,
        "old_role": old_role,
        "new_role": new_role,
        "old_device_info": old_device_info,
        "new_device_info": new_device_info,
        "mismatch_warnings": mismatch_warnings,
    }
