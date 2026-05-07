from app.models import ConfigData, Finding


RULE_CATEGORIES: dict[str, str] = {
    "R001": "operations",
    "R002": "security",
    "R003": "operations",
    "R004": "operations",
    "R005": "routing",
    "R006": "routing",
    "R007": "security",
    "R008": "security",
    "R009": "security",
    "R010": "security",
    "R011": "security",
    "R012": "security",
    "R013": "security",
    "R014": "security",
    "R015": "operations",
    "R016": "operations",
    "R017": "compliance",
    "R018": "security",
    "R019": "operations",
    "R020": "security",
    "R021": "security",
    "R022": "security",
    "R023": "security",
    "R024": "operations",
    "R025": "l2",
    "R026": "l2",
    "R027": "security",
    "R028": "security",
    "R029": "l2",
    "R030": "l2",
    "R031": "security",
    "R032": "security",
    "R033": "l2",
    "R034": "l2",
    "R035": "l2",
    "R036": "l2",
    "R037": "l2",
    "R038": "operations",
    "R039": "operations",
    "R040": "security",
    "R041": "security",
    "R042": "operations",
    "R043": "operations",
    "R044": "security",
    "R045": "l2",
}


def _rule_unassigned_vlan(data: ConfigData) -> list[Finding]:
    used_vlans: set[int] = set()
    for intf in data.interfaces:
        if intf.access_vlan is not None:
            used_vlans.add(intf.access_vlan)
        used_vlans.update(intf.trunk_vlans)

    findings: list[Finding] = []
    for vlan in sorted(data.vlans - used_vlans):
        findings.append(
            Finding(
                rule_id="R001",
                severity="medium",
                message=f"VLAN {vlan} tanımlı ancak hiçbir interface'te kullanılmıyor.",
                context=f"vlan {vlan}",
            )
        )
    return findings


def _rule_acl_any_any(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for acl in data.acls:
        if (
            acl.action == "permit"
            and acl.protocol == "ip"
            and "any" in acl.src
            and "any" in acl.dst
        ):
            findings.append(
                Finding(
                    rule_id="R002",
                    severity="high",
                    message=(
                        f"ACL '{acl.acl_name}' içinde fazla geniş bir izin kuralı var "
                        "(any any)."
                    ),
                    context=acl.raw_line,
                )
            )
    return findings


def _rule_shutdown_trunk(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.shutdown and intf.switchport_mode == "trunk":
            findings.append(
                Finding(
                    rule_id="R003",
                    severity="medium",
                    message=(
                        f"{intf.name} shutdown durumda ama trunk olarak yapılandırılmış."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_missing_description(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if not intf.description:
            findings.append(
                Finding(
                    rule_id="R004",
                    severity="low",
                    message=f"{intf.name} interface'inde description eksik.",
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_ospf_area_mismatch(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.ospf_process_id is None or intf.ospf_area is None:
            continue
        process = data.ospf_processes.get(intf.ospf_process_id)
        if process is None or not process.areas:
            continue
        if len(process.areas) == 1:
            expected_area = next(iter(process.areas))
            if intf.ospf_area != expected_area:
                findings.append(
                    Finding(
                        rule_id="R005",
                        severity="medium",
                        message=(
                            f"{intf.name} üzerindeki OSPF area ({intf.ospf_area}), "
                            f"process {intf.ospf_process_id} beklenen area "
                            f"({expected_area}) ile uyuşmuyor."
                        ),
                        context=f"interface {intf.name}",
                    )
                )
    return findings


def _rule_bgp_neighbor_missing_route_map(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None:
            continue
        if not neighbor.route_maps:
            findings.append(
                Finding(
                    rule_id="R006",
                    severity="high",
                    message=(
                        f"BGP neighbor {neighbor.neighbor_ip} tanımlı ancak route-map "
                        "uygulanmamış."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip} remote-as {neighbor.remote_as}",
                )
            )
    return findings


def _rule_ssh_v1_enabled(data: ConfigData) -> list[Finding]:
    if data.ssh_version == 1:
        return [
            Finding(
                rule_id="R007",
                severity="high",
                message="SSH v1 aktif görünüyor. CIS için SSH v2 kullanılmalı.",
                context="ip ssh version 1",
            )
        ]
    return []


def _rule_console_timeout_missing(data: ConfigData) -> list[Finding]:
    if not data.console_exec_timeout_set:
        return [
            Finding(
                rule_id="R008",
                severity="medium",
                message="Console line için exec-timeout tanımı bulunamadı.",
                context="line console 0",
            )
        ]
    return []


def _rule_snmp_default_community(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for community in data.snmp_communities:
        if community.name.lower() in {"public", "private"}:
            findings.append(
                Finding(
                    rule_id="R009",
                    severity="high",
                    message=(
                        f"SNMP community '{community.name}' varsayılan/değiştirilmemiş "
                        "değerde görünüyor (v1/v2c riski)."
                    ),
                    context=community.raw_line,
                )
            )
    return findings


def _rule_enable_secret_missing(data: ConfigData) -> list[Finding]:
    if not data.enable_secret_set:
        return [
            Finding(
                rule_id="R010",
                severity="high",
                message="`enable secret` tanımı bulunamadı.",
                context="global configuration",
            )
        ]
    return []


def _rule_service_password_encryption_missing(data: ConfigData) -> list[Finding]:
    if not data.service_password_encryption_enabled:
        return [
            Finding(
                rule_id="R011",
                severity="medium",
                message="`service password-encryption` etkin değil.",
                context="global configuration",
            )
        ]
    return []


def _rule_vty_telnet_enabled(data: ConfigData) -> list[Finding]:
    if data.vty_has_telnet_transport:
        return [
            Finding(
                rule_id="R012",
                severity="high",
                message="VTY hatlarında `transport input telnet` tespit edildi.",
                context="line vty",
            )
        ]
    return []


def _rule_http_server_enabled(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    if data.ip_http_server_enabled:
        findings.append(
            Finding(
                rule_id="R013",
                severity="high",
                message="`ip http server` etkin. Yönetim için HTTP açık olmamalı.",
                context="ip http server",
            )
        )
    return findings


def _rule_aaa_new_model_missing(data: ConfigData) -> list[Finding]:
    if not data.aaa_new_model_enabled:
        return [
            Finding(
                rule_id="R014",
                severity="high",
                message="`aaa new-model` aktif değil. Merkezi kimlik doğrulama yok.",
                context="global configuration",
            )
        ]
    return []


def _rule_logging_host_missing(data: ConfigData) -> list[Finding]:
    if not data.has_logging_host:
        return [
            Finding(
                rule_id="R015",
                severity="medium",
                message="Uzak syslog sunucusu (`logging host`) tanımlı değil.",
                context="global configuration",
            )
        ]
    return []


def _rule_ntp_server_missing(data: ConfigData) -> list[Finding]:
    if not data.has_ntp_server:
        return [
            Finding(
                rule_id="R016",
                severity="medium",
                message="`ntp server` tanımlı değil. Cihaz saati senkron değil.",
                context="global configuration",
            )
        ]
    return []


def _rule_banner_motd_missing(data: ConfigData) -> list[Finding]:
    if not data.has_banner_motd:
        return [
            Finding(
                rule_id="R017",
                severity="medium",
                message="`banner motd` tanımlı değil. Yasal/uyarı bildirimi eksik.",
                context="global configuration",
            )
        ]
    return []


def _rule_login_block_missing(data: ConfigData) -> list[Finding]:
    if not data.has_login_block_for:
        return [
            Finding(
                rule_id="R018",
                severity="high",
                message="`login block-for` tanımlı değil. Brute-force koruması yok.",
                context="global configuration",
            )
        ]
    return []


def _rule_domain_lookup_enabled(data: ConfigData) -> list[Finding]:
    if not data.ip_domain_lookup_disabled:
        return [
            Finding(
                rule_id="R019",
                severity="low",
                message="`no ip domain-lookup` ayarlanmamış. Yanlış komutlar DNS arayabilir.",
                context="global configuration",
            )
        ]
    return []


def _rule_finger_enabled(data: ConfigData) -> list[Finding]:
    if data.service_finger_enabled:
        return [
            Finding(
                rule_id="R020",
                severity="medium",
                message="`service finger` veya `ip finger` aktif. Bilgi sızıntı riski.",
                context="global configuration",
            )
        ]
    return []


def _rule_source_route_enabled(data: ConfigData) -> list[Finding]:
    if not data.ip_source_route_disabled:
        return [
            Finding(
                rule_id="R021",
                severity="medium",
                message="`no ip source-route` ayarlanmamış. IP source routing açık.",
                context="global configuration",
            )
        ]
    return []


def _rule_service_pad_enabled(data: ConfigData) -> list[Finding]:
    if not data.service_pad_disabled:
        return [
            Finding(
                rule_id="R022",
                severity="medium",
                message="`no service pad` ayarlanmamış. PAD servisi varsayılan açık.",
                context="global configuration",
            )
        ]
    return []


def _rule_cdp_globally_enabled(data: ConfigData) -> list[Finding]:
    if not data.cdp_run_disabled:
        return [
            Finding(
                rule_id="R023",
                severity="medium",
                message="`no cdp run` ayarlanmamış. Cihaz bilgisi CDP üzerinden yayınlanıyor.",
                context="global configuration",
            )
        ]
    return []


def _rule_clock_timezone_missing(data: ConfigData) -> list[Finding]:
    if not data.has_clock_timezone:
        return [
            Finding(
                rule_id="R024",
                severity="medium",
                message="`clock timezone` tanımlı değil. Log zaman dilimi belirsiz.",
                context="global configuration",
            )
        ]
    return []


def _rule_bpduguard_default_missing(data: ConfigData) -> list[Finding]:
    if not data.bpduguard_default_enabled:
        return [
            Finding(
                rule_id="R025",
                severity="medium",
                message=(
                    "`spanning-tree portfast bpduguard default` tanımlı değil. "
                    "Erişim portları BPDU saldırısına açık."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_trunk_native_vlan_default(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.switchport_mode != "trunk":
            continue
        if intf.trunk_native_vlan is None or intf.trunk_native_vlan == 1:
            findings.append(
                Finding(
                    rule_id="R026",
                    severity="medium",
                    message=(
                        f"{intf.name} trunk arayüzünde native VLAN varsayılan (1) "
                        "veya tanımlı değil. VLAN hopping riski."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_vty_no_access_class(data: ConfigData) -> list[Finding]:
    if not data.vty_has_access_class:
        return [
            Finding(
                rule_id="R027",
                severity="medium",
                message=(
                    "VTY hatlarında `access-class` tanımlı değil. Yönetim erişimi "
                    "IP bazlı sınırlandırılmamış."
                ),
                context="line vty",
            )
        ]
    return []


def _rule_enable_password_cleartext(data: ConfigData) -> list[Finding]:
    if data.enable_password_cleartext:
        return [
            Finding(
                rule_id="R028",
                severity="high",
                message=(
                    "`enable password` (zayıf) tanımı tespit edildi. Yerine `enable "
                    "secret` kullanın."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_dhcp_snooping_missing(data: ConfigData) -> list[Finding]:
    if not data.dhcp_snooping_enabled:
        return [
            Finding(
                rule_id="R029",
                severity="high",
                message=(
                    "`ip dhcp snooping` aktif değil. Sahte DHCP sunucuları riski var."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_arp_inspection_missing(data: ConfigData) -> list[Finding]:
    if not data.arp_inspection_enabled:
        return [
            Finding(
                rule_id="R030",
                severity="medium",
                message=(
                    "`ip arp inspection` tanımlı değil. ARP spoofing saldırılarına açık."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_vty_exec_timeout_missing(data: ConfigData) -> list[Finding]:
    if not data.vty_exec_timeout_set:
        return [
            Finding(
                rule_id="R031",
                severity="medium",
                message="VTY için `exec-timeout` tanımı bulunamadı.",
                context="line vty",
            )
        ]
    return []


def _rule_aux_not_disabled(data: ConfigData) -> list[Finding]:
    if data.aux_section_seen and not data.aux_no_exec_set:
        return [
            Finding(
                rule_id="R032",
                severity="medium",
                message="`line aux` tanımlı ama `no exec` ile devre dışı bırakılmamış.",
                context="line aux 0",
            )
        ]
    if not data.aux_section_seen:
        return [
            Finding(
                rule_id="R032",
                severity="low",
                message="`line aux 0` üzerinde `no exec` ile pasifleştirme önerilir.",
                context="line aux 0",
            )
        ]
    return []


def _rule_spanning_tree_mode_missing(data: ConfigData) -> list[Finding]:
    if data.spanning_tree_mode is None:
        return [
            Finding(
                rule_id="R033",
                severity="medium",
                message=(
                    "`spanning-tree mode` tanımlı değil. Önerilen: `rapid-pvst` veya "
                    "`mst`."
                ),
                context="global configuration",
            )
        ]
    if data.spanning_tree_mode == "pvst":
        return [
            Finding(
                rule_id="R033",
                severity="low",
                message=(
                    "`spanning-tree mode pvst` (eski) kullanılıyor. `rapid-pvst` "
                    "veya `mst` önerilir."
                ),
                context=f"spanning-tree mode {data.spanning_tree_mode}",
            )
        ]
    return []


def _rule_trunk_dtp_open(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.switchport_mode == "trunk" and not intf.nonegotiate_set:
            findings.append(
                Finding(
                    rule_id="R034",
                    severity="medium",
                    message=(
                        f"{intf.name} trunk arayüzünde `switchport nonegotiate` yok. "
                        "DTP açık, switch spoofing riski."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_access_vlan_default(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.switchport_mode == "access" and intf.access_vlan == 1:
            findings.append(
                Finding(
                    rule_id="R035",
                    severity="medium",
                    message=(
                        f"{intf.name} access portu varsayılan VLAN 1'i kullanıyor. "
                        "Özel bir VLAN'a alın."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_access_port_security_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.switchport_mode == "access" and not intf.port_security_enabled:
            findings.append(
                Finding(
                    rule_id="R036",
                    severity="medium",
                    message=(
                        f"{intf.name} access portunda `switchport port-security` "
                        "tanımlı değil."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_access_port_bpduguard_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    if data.bpduguard_default_enabled:
        return findings
    for intf in data.interfaces:
        if intf.switchport_mode == "access" and not intf.bpduguard_enabled:
            findings.append(
                Finding(
                    rule_id="R037",
                    severity="medium",
                    message=(
                        f"{intf.name} access portunda `spanning-tree bpduguard "
                        "enable` tanımlı değil."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_tcp_keepalives_missing(data: ConfigData) -> list[Finding]:
    if not data.has_service_tcp_keepalives:
        return [
            Finding(
                rule_id="R038",
                severity="low",
                message=(
                    "`service tcp-keepalives-in/out` etkin değil. Ölü oturumlar "
                    "açık kalabilir."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_logging_buffered_missing(data: ConfigData) -> list[Finding]:
    if not data.has_logging_buffered:
        return [
            Finding(
                rule_id="R039",
                severity="low",
                message="`logging buffered` tanımlı değil. Yerel log buffer'ı yok.",
                context="global configuration",
            )
        ]
    return []


def _rule_ssh_timeout_missing(data: ConfigData) -> list[Finding]:
    if not data.ssh_timeout_set:
        return [
            Finding(
                rule_id="R040",
                severity="low",
                message="`ip ssh time-out` tanımlı değil (önerilen 60).",
                context="global configuration",
            )
        ]
    return []


def _rule_ssh_auth_retries_missing(data: ConfigData) -> list[Finding]:
    if not data.ssh_auth_retries_set:
        return [
            Finding(
                rule_id="R041",
                severity="low",
                message="`ip ssh authentication-retries` tanımlı değil (önerilen 3).",
                context="global configuration",
            )
        ]
    return []


def _rule_archive_missing(data: ConfigData) -> list[Finding]:
    if not data.archive_enabled:
        return [
            Finding(
                rule_id="R042",
                severity="low",
                message="`archive` (config archive) tanımlı değil. Değişiklik izi tutulmuyor.",
                context="global configuration",
            )
        ]
    return []


def _rule_loopback_missing(data: ConfigData) -> list[Finding]:
    has_loopback = any(
        intf.name.lower().startswith("loopback") for intf in data.interfaces
    )
    if not has_loopback:
        return [
            Finding(
                rule_id="R043",
                severity="low",
                message=(
                    "Loopback arayüzü tanımlı değil. Yönetim/routing kararlılığı için "
                    "Loopback önerilir."
                ),
                context="interface Loopback0",
            )
        ]
    return []


def _rule_access_port_cdp_disabled_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    if data.cdp_run_disabled:
        return findings
    for intf in data.interfaces:
        if intf.switchport_mode == "access" and not intf.cdp_disabled:
            findings.append(
                Finding(
                    rule_id="R044",
                    severity="low",
                    message=(
                        f"{intf.name} access portunda `no cdp enable` tanımlı değil. "
                        "Kullanıcı portunda CDP gereksiz."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def _rule_access_port_storm_control_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if intf.switchport_mode == "access" and not intf.storm_control_enabled:
            findings.append(
                Finding(
                    rule_id="R045",
                    severity="low",
                    message=(
                        f"{intf.name} access portunda `storm-control` tanımlı değil."
                    ),
                    context=f"interface {intf.name}",
                )
            )
    return findings


def run_rules(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for rule in (
        _rule_unassigned_vlan,
        _rule_acl_any_any,
        _rule_shutdown_trunk,
        _rule_missing_description,
        _rule_ospf_area_mismatch,
        _rule_bgp_neighbor_missing_route_map,
        _rule_ssh_v1_enabled,
        _rule_console_timeout_missing,
        _rule_snmp_default_community,
        _rule_enable_secret_missing,
        _rule_service_password_encryption_missing,
        _rule_vty_telnet_enabled,
        _rule_http_server_enabled,
        _rule_aaa_new_model_missing,
        _rule_logging_host_missing,
        _rule_ntp_server_missing,
        _rule_banner_motd_missing,
        _rule_login_block_missing,
        _rule_domain_lookup_enabled,
        _rule_finger_enabled,
        _rule_source_route_enabled,
        _rule_service_pad_enabled,
        _rule_cdp_globally_enabled,
        _rule_clock_timezone_missing,
        _rule_bpduguard_default_missing,
        _rule_trunk_native_vlan_default,
        _rule_vty_no_access_class,
        _rule_enable_password_cleartext,
        _rule_dhcp_snooping_missing,
        _rule_arp_inspection_missing,
        _rule_vty_exec_timeout_missing,
        _rule_aux_not_disabled,
        _rule_spanning_tree_mode_missing,
        _rule_trunk_dtp_open,
        _rule_access_vlan_default,
        _rule_access_port_security_missing,
        _rule_access_port_bpduguard_missing,
        _rule_tcp_keepalives_missing,
        _rule_logging_buffered_missing,
        _rule_ssh_timeout_missing,
        _rule_ssh_auth_retries_missing,
        _rule_archive_missing,
        _rule_loopback_missing,
        _rule_access_port_cdp_disabled_missing,
        _rule_access_port_storm_control_missing,
    ):
        findings.extend(rule(data))
    for finding in findings:
        finding.category = RULE_CATEGORIES.get(finding.rule_id, "general")
    return findings
