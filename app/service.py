import difflib
import hashlib
import re
from collections import defaultdict

from app.ai_commentary import format_report
from app.models import Finding
from app.parser import parse_cisco_ios_config
from app.device_type_policy import (
    DEVICE_TYPE_LABELS_TR,
    DEVICE_ROLE_LABELS,
    filter_findings_by_device_type,
    filter_findings_by_device_role,
    infer_device_type,
    infer_device_role,
)
from app.rules import RULE_CATEGORIES, run_rules
from app.secret_scanner import mask_credentials_in_line, scan_secrets


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
        "Fortinet FortiOS",
        r"^\s*config\s+system\s+global\s*$"
        r"|^\s*config\s+vdom\s*$"
        r"|^\s*config\s+firewall\s+(policy|address|addrgrp|service|vip)\s*$"
        r"|^\s*config\s+router\s+(static|policy|bgp|ospf)\s*$"
        r"|^\s*config\s+vpn\s+ipsec\s+phase\d+-interface\s*$"
        r"|^\s*set\s+vdom\s+",
    ),
    (
        "Palo Alto PAN-OS",
        r"^\s*set\s+deviceconfig\s+"
        r"|^\s*set\s+network\s+virtual-router\s+"
        r"|^\s*set\s+vsys\s+"
        r"|^\s*set\s+profiles\s+(security|decryption|url-filtering)\s+"
        r"|^\s*set\s+rulebase\s+security\s+rules\s+",
    ),
    (
        "MikroTik RouterOS",
        r"^\s*/(?:ip|ipv6|interface|routing|system|queue|tool|disk|certificate|ppp|snmp)\s+"
        r"|^\s*#\s+.*\bby\s+RouterOS\s+"
        r"|^\s*\[\S+@(?:MikroTik|mikrotik)\]\s*>",
    ),
    (
        "F5 BIG-IP",
        r"^\s*ltm\s+(pool|node|virtual|snat|monitor|rule|persistence|policy)\s+"
        r"|^\s*apm\s+"
        r"|^\s*net\s+self\s+"
        r"|^\s*auth\s+partition\s+"
        r"|^\s*security\s+firewall\s+",
    ),
    (
        "Cisco ASA",
        r"^\s*nat\s*\(\s*\S+\s*,\s*\S+\s*\)\s+"
        r"|^\s*same-security-traffic\s+"
        r"|^\s*access-group\s+\S+\s+(in|out)\s+interface\s+"
        r"|^\s*threat-detection\s+"
        r"|^\s*policy-map\s+global_policy\b",
    ),
    (
        "Nokia SR OS",
        r"^\s*#+\s*TiMOS-[A-Z0-9-]+"
        r"|^\s*configure\s+service\s+"
        r"|^\s*configure\s+router\s+\""
        r"|^\s*sap\s+\S+\s+\S+\s+create\s+"
        r"|^\s*epipe\s+\d+\s+create\s+",
    ),
    (
        "Extreme Networks EXOS",
        r"^\s*create\s+vlan\s+"
        r"|^\s*configure\s+vlan\s+\S+\s+(add|delete|tag|untag)\s+"
        r"|^\s*enable\s+sharing\s+\d+\s+grouping\s+"
        r"|^\s*configure\s+slot\s+\d+\s+"
        r"|^\s*disable\s+clipaging\s*$",
    ),
    (
        "Brocade / Ruckus ICX (FastIron)",
        r"^\s*vlan\s+\d+\s+name\s+.+\s+by\s+port\b"
        r"|^\s*spanning-tree\s+802-1w\b"
        r"|^\s*spanning-tree\s+single\s+802-1w\b"
        r"|^\s*inline\s+power\s+by\s+port\b"
        r"|^\s*stack\s+unit\s+\d+\s+"
        r"|^\s*default\s+802-1x\s+",
    ),
    (
        "Cumulus Linux",
        r"^\s*iface\s+swp\d+"
        r"|^\s*auto\s+bridge\b"
        r"|^\s*nv\s+set\s+"
        r"|^\s*#\s+This\s+file\s+describes\s+the\s+network\s+interfaces",
    ),
    (
        "H3C Comware",
        r"^\s*radius[- ]scheme\s+"
        r"|^\s*hwtacacs-server\s+\d{1,3}(?:\.\d{1,3}){3}\b"
        r"|^\s*domain\s+default\s+allow\s+"
        r"|^\s*ip\s+https\s+certificate\s+"
        r"|^\s*super\s+password\s+simple\s+",
    ),
    (
        "SonicWall",
        r"^\s*address-object\s+ipv4\s+"
        r"|^\s*ipv4\s+name-servers\s+"
        r"|^\s*network\s+object\s+ipv4\b"
        r"|^\s*policy\s+ipv4\s+from\s+",
    ),
    (
        "Juniper",
        r"^\s*set\s+(system|interfaces|protocols|routing-options|firewall|chassis)\s+\S+"
        r"|^\s*version\s+\S*JUNOS\S*\s*;?\s*$"
        r"|^\s*apply-groups\s+"
        r"|^\s*groups\s*\{",
    ),
    (
        "Huawei",
        r"^\s*sysname\s+\S+"
        r"|^\s*display\s+current-configuration"
        r"|^\s*super\s+password\s+"
        r"|^\s*vlan\s+batch\b"
        r"|^\s*info-center\b"
        r"|^\s*user-interface\s+(vty|con|console)\b"
        r"|^\s*interface\s+Vlanif\d+"
        r"|^\s*stp\s+mode\b"
        r"|^\s*stp\s+region-configuration\b"
        r"|^\s*stp\s+enable\b"
        r"|^\s*undo\s+\S+"
        r"|^\s*hwtacacs-server\s+template\b"
        r"|^\s*radius-server\s+template\b"
        r"|^\s*aaa\s+authentication-scheme\b"
        r"|^\s*aaa\s+authorization-scheme\b"
        r"|^\s*traffic-policy\s+\S+\s+(inbound|outbound)\b"
        r"|^\s*ip\s+vpn-instance\b"
        r"|^\s*vrrp\s+vrid\s+\d+\s+virtual-ip\b"
        r"|^\s*dhcp\s+server\s+ip-range\b"
        r"|^\s*port\s+link-type\b"
        r"|^\s*port\s+default\s+vlan\b"
        r"|^\s*command-privilege\s+level\b"
        r"|^\s*hotkey\s+CTRL_\w+"
        r"|^\s*clock\s+timezone\s+\S+\s+add\b"
        r"|^\s*nqa\s+test-instance\b"
        r"|^\s*netconf\s+ssh\s+server\s+enable\b",
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
        if has_cisco_ios_markers:
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


_NEIGHBOR_AGG_RULE_IDS = frozenset({"R006", "R051", "R057", "R058", "R060", "R061"})
_SECRET_RULE_IDS = frozenset({f"R{i:03d}" for i in range(62, 69)})


def _rule_category(rule_id: str) -> str:
    return RULE_CATEGORIES.get(rule_id, "general")


def _iface_from_context(context: str) -> str | None:
    m = re.match(r"^\s*interface\s+(\S+)\s*$", context.strip(), flags=re.IGNORECASE)
    return m.group(1) if m else None


def _message_body_after_interface_name(message: str, iface: str) -> str:
    if not iface:
        return message
    variants = [
        f"{iface} üzerindeki ",
        f"{iface} üzerinde ",
        f"{iface} interface'inde ",
        f"{iface} trunk arayüzünde ",
        f"{iface} access portu ",
        f"{iface} access portunda ",
        f"{iface} L3 interface'inde ",
        f"{iface} shutdown durumda ",
        f"{iface} ",
    ]
    for pref in sorted(variants, key=len, reverse=True):
        if message.startswith(pref):
            return message[len(pref) :].lstrip()
    return message


def _neutralize_ipv4(msg: str) -> str:
    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<peer>", msg)


def _format_vlan_runs(nums: list[int]) -> str:
    if not nums:
        return ""
    nums = sorted(set(nums))
    parts: list[str] = []
    i = 0
    while i < len(nums):
        start = nums[i]
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        end = nums[j]
        if start == end:
            parts.append(str(start))
        elif end == start + 1:
            parts.extend([str(start), str(end)])
        else:
            parts.append(f"{start}-{end}")
        i = j + 1
    text = ", ".join(parts)
    if len(text) > 240:
        return text[:237] + "..."
    return text


def _merge_r001_unused_vlans(group: list[Finding]) -> Finding:
    vlans: list[int] = []
    for item in group:
        m = re.search(r"vlan\s+(\d+)", item.context.strip(), flags=re.IGNORECASE)
        if m:
            vlans.append(int(m.group(1)))
    vlans = sorted(set(vlans))
    summary = _format_vlan_runs(vlans)
    msg = (
        f"Tanımlı ancak hiçbir interface'te kullanılmayan VLAN: {len(vlans)} adet "
        f"({summary})."
    )
    ctx = ", ".join(f"vlan {v}" for v in vlans[:40])
    if len(vlans) > 40:
        ctx += f" (+{len(vlans) - 40} VLAN daha)"
    return Finding(
        rule_id="R001",
        severity=group[0].severity,
        message=msg,
        context=ctx,
        category=_rule_category("R001"),
        stable_key="R001:unused-vlan-batch",
        occurrence_count=len(vlans),
    )


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    """Aynı kuralın çoklu arayüz/neighbor/satır tekrarlarını tek bulguda toplar (denetim UX)."""
    if len(findings) < 2:
        return findings

    r001: list[Finding] = []
    iface_groups: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
    neighbor_groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    secret_groups: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    rest: list[Finding] = []

    for item in findings:
        rid = item.rule_id
        if rid == "R001" and re.match(r"^\s*vlan\s+\d+", item.context.strip(), flags=re.IGNORECASE):
            r001.append(item)
            continue
        if rid in _SECRET_RULE_IDS:
            secret_groups[(rid, item.severity, item.message)].append(item)
            continue
        ctx = item.context.strip()
        if rid in _NEIGHBOR_AGG_RULE_IDS and ctx.lower().startswith("neighbor "):
            neighbor_groups[(rid, item.severity)].append(item)
            continue
        iface = _iface_from_context(item.context)
        if iface:
            body = _message_body_after_interface_name(item.message, iface)
            cat = _rule_category(rid)
            iface_groups[(rid, item.severity, cat, body)].append(item)
            continue
        rest.append(item)

    out: list[Finding] = rest

    if len(r001) > 1:
        out.append(_merge_r001_unused_vlans(r001))
    elif r001:
        out.append(r001[0])

    for group in secret_groups.values():
        if len(group) == 1:
            out.append(group[0])
            continue
        lines = list(dict.fromkeys(g.context for g in group))
        shown = lines[:18]
        ctx = "\n".join(shown)
        if len(lines) > 18:
            ctx += f"\n… (+{len(lines) - 18} ek satır, toplam {len(group)} eşleşme)"
        elif len(group) > len(lines):
            ctx += f"\n(toplam {len(group)} eşleşme)"
        sk = f"{group[0].rule_id}:secret-batch"
        out.append(
            Finding(
                rule_id=group[0].rule_id,
                severity=group[0].severity,
                message=group[0].message,
                context=ctx,
                category=_rule_category(group[0].rule_id),
                stable_key=sk,
                occurrence_count=len(group),
            )
        )

    for (rid, sev), group in neighbor_groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        neutral = _neutralize_ipv4(group[0].message)
        ctx_parts = [g.context.strip() for g in group[:25]]
        ctx = ", ".join(ctx_parts)
        if len(group) > 25:
            ctx += f" (+{len(group) - 25} neighbor daha)"
        sk = f"{rid}:{sev}:neighbor-batch"
        out.append(
            Finding(
                rule_id=rid,
                severity=sev,
                message=f"{len(group)} BGP neighbor kaydında aynı eksiklik: {neutral}",
                context=ctx,
                category=_rule_category(rid),
                stable_key=sk,
                occurrence_count=len(group),
            )
        )

    for (rid, sev, cat, body), group in iface_groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        names = []
        for g in group:
            n = _iface_from_context(g.context)
            if n:
                names.append(n)
        names = sorted(set(names), key=lambda s: s.lower())
        shown = names[:30]
        ctx = ", ".join(f"interface {n}" for n in shown)
        if len(names) > 30:
            ctx += f" (+{len(names) - 30} arayüz daha)"
        h = hashlib.sha256(f"{rid}|{sev}|{body}".encode("utf-8")).hexdigest()[:10]
        sk = f"{rid}:{sev}:iface-batch:{h}"
        msg = f"{len(group)} arayüzde aynı eksiklik: {body}"
        out.append(
            Finding(
                rule_id=rid,
                severity=sev,
                message=msg,
                context=ctx,
                category=cat,
                stable_key=sk,
                occurrence_count=len(group),
            )
        )

    return out


def audit_bundle(config_text: str) -> tuple[list[dict], dict]:
    """Parse + cihaz türü tahmini + kurallar + secret + toplulaştırma; rapor ve device_info."""
    parsed = parse_cisco_ios_config(config_text)
    dt_key = infer_device_type(config_text)
    dr_key = infer_device_role(config_text, dt_key)
    
    findings = run_rules(parsed)
    findings = filter_findings_by_device_type(findings, dt_key)
    findings = filter_findings_by_device_role(findings, dr_key)
    
    findings.extend(scan_secrets(config_text))
    findings = aggregate_findings(findings)
    report = format_report(findings)
    info = detect_device_info(config_text)
    info["device_type"] = dt_key
    info["device_type_label"] = DEVICE_TYPE_LABELS_TR.get(dt_key, dt_key)
    info["device_role"] = dr_key
    info["device_role_label"] = DEVICE_ROLE_LABELS.get(dr_key, dr_key)
    info["device_type_source"] = "inferred"
    info["device_type_note"] = "Cihaz türü ve rolü otomatik tahmin edildi"
    return report, info


def audit_config_text(config_text: str) -> list[dict]:
    return audit_bundle(config_text)[0]


def count_categories(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in findings:
        cat = item.get("category", "general")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def _finding_key(item: dict) -> tuple[str, str, str]:
    stable = item.get("stable_key")
    if stable:
        return (item["rule_id"], stable, "")
    return (item["rule_id"], item["context"], item["message"])


def _extract_changed_lines(old_text: str, new_text: str) -> list[dict]:
    diff_lines = difflib.ndiff(old_text.splitlines(), new_text.splitlines())
    changed: list[dict] = []
    for line in diff_lines:
        if line.startswith("+ "):
            content = line[2:].strip()
            if content:
                changed.append(
                    {
                        "source": "new",
                        "prefix": "+",
                        "line": mask_credentials_in_line(content),
                    }
                )
        elif line.startswith("- "):
            content = line[2:].strip()
            if content:
                changed.append(
                    {
                        "source": "old",
                        "prefix": "-",
                        "line": mask_credentials_in_line(content),
                    }
                )
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
        text = mask_credentials_in_line(raw.strip())
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
                            "old_line": mask_credentials_in_line(old_line.strip()),
                            "new_line": mask_credentials_in_line(new_line.strip()),
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
    old_report, old_device_info = audit_bundle(old_text)
    new_report, new_device_info = audit_bundle(new_text)

    old_map = {_finding_key(item): item for item in old_report}
    new_map = {_finding_key(item): item for item in new_report}

    new_findings = [item for key, item in new_map.items() if key not in old_map]
    resolved_findings = [item for key, item in old_map.items() if key not in new_map]
    changed_lines = _extract_changed_lines(old_text, new_text)
    diff_groups = _build_diff_groups(old_text, new_text)
    changed_set = {line["line"].lower() for line in changed_lines}


    def _context_affected(ctx: str) -> bool:
        ctx_lower = ctx.lower().strip()
        if not ctx_lower:
            return False
        if ctx_lower in changed_set:
            return True
        if len(ctx_lower) >= 8:
            prefix = ctx_lower + " "
            if any(changed_line.startswith(prefix) for changed_line in changed_set):
                return True
        return False

    changed_line_findings = [
        item for item in new_report if _context_affected(item["context"])
    ]

    old_hostname = _extract_hostname(old_text)
    new_hostname = _extract_hostname(new_text)
    old_inferred = infer_device_type(old_text)
    new_inferred = infer_device_type(new_text)
    mismatch_warnings: list[str] = []
    if old_device_info.get("device_type") != new_device_info.get("device_type"):
        mismatch_warnings.append(
            "Konfigürasyon imzasına göre tahmin edilen cihaz türleri iki dosya arasında "
            "farklı görünüyor "
            f"(eski: {old_device_info.get('device_type_label')}, "
            f"yeni: {new_device_info.get('device_type_label')}). "
            "Aynı cihazın iki sürümünü karşılaştırdığınızdan emin olun."
        )
    if old_hostname and new_hostname and old_hostname != new_hostname:
        mismatch_warnings.append(
            f"Yüklenen iki dosyanın hostname'i farklı: '{old_hostname}' ve "
            f"'{new_hostname}'. Diff sonucu yanıltıcı olabilir."
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
        "old_device_type": old_inferred,
        "new_device_type": new_inferred,
        "old_device_info": old_device_info,
        "new_device_info": new_device_info,
        "mismatch_warnings": mismatch_warnings,
    }
