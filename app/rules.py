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
    "R023": "operations",
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
    "R044": "operations",
    "R045": "l2",
    "R046": "security",
    "R047": "security",
    "R048": "security",
    "R049": "security",
    "R050": "routing",
    "R051": "routing",
    "R052": "security",
    "R053": "routing",
    "R054": "routing",
    "R055": "routing",
    "R056": "routing",
    "R057": "routing",
    "R058": "routing",
    "R059": "routing",
    "R060": "routing",
    "R061": "routing",
    "R062": "security",
    "R063": "security",
    "R064": "security",
    "R065": "security",
    "R066": "security",
    "R067": "security",
    "R068": "security",
    "R069": "compliance",
    "R070": "operations",
    "R071": "security",
    "R072": "security",
    "R073": "security",
    "R074": "operations",
    "R075": "operations",
    "R076": "operations",
    "R077": "operations",
    "R078": "security",
    "R079": "operations",
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
                message=f"VLAN {vlan} tanımlı, ancak hiçbir interface üzerinde kullanılmıyor.",
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
                    message=f"{intf.name} shutdown durumda, ancak trunk olarak yapılandırılmış.",
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
                severity="info",
                message=(
                    "`no ip domain-lookup` ayarlanmamış (operasyonel iyi uygulama; "
                    "güvenlik zafiyeti değildir). Yanlış komutlar DNS sorgusu tetikleyebilir."
                ),
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
                severity="info",
                message=(
                    "`no cdp run` tanımlı değil (düşük öncelik: CDP ile komşu/cihaz "
                    "bilgisi görünür; yönlendirme protokolü kimlik doğrulama eksikliğiyle "
                    "aynı risk sınıfında değildir)."
                ),
                context="global configuration",
            )
        ]
    return []


def _rule_clock_timezone_missing(data: ConfigData) -> list[Finding]:
    if not data.has_clock_timezone:
        return [
            Finding(
                rule_id="R024",
                severity="low",
                message=(
                    "`clock timezone` tanımlı değil (operasyonel/denetim önerisi). "
                    "Log ve korelasyon için saat dilimi belirsiz kalır."
                ),
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
                severity="info",
                message=(
                    "`service tcp-keepalives-in/out` etkin değil (operasyonel öneri; "
                    "güvenlik bulgusu değildir). Ölü TCP oturumları kaynak tüketebilir."
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
                message="`ip ssh time-out` tanımlı değil (önerilen süre: 60 saniye).",
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
                severity="info",
                message=(
                    "`archive` (config archive) tanımlı değil (operasyonel/denetim önerisi; "
                    "doğrudan güvenlik açığı değildir). Değişiklik izi tutulmuyor."
                ),
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
                    severity="info",
                    message=(
                        f"{intf.name} access portunda `no cdp enable` tanımlı değil "
                        "(operasyonel öneri; komşuluk bilgisi sızıntısını azaltır, "
                        "tipik bir güvenlik bulgusu olarak sınıflandırılmaz)."
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


def _rule_snmpv3_missing(data: ConfigData) -> list[Finding]:
    if not data.snmp_communities:
        return []
    if data.snmpv3_configured:
        return []
    return [
        Finding(
            rule_id="R046",
            severity="high",
            message=(
                "SNMP v1/v2c community kullanılıyor ama SNMPv3 user/group tanımlı değil."
            ),
            context="snmp-server",
        )
    ]


def _rule_snmp_community_no_acl(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for community in data.snmp_communities:
        if not community.acl_name:
            findings.append(
                Finding(
                    rule_id="R047",
                    severity="high",
                    message=(
                        f"SNMP community `{community.name}` ACL ile kısıtlanmamış."
                    ),
                    context=community.raw_line,
                )
            )
    return findings


def _rule_copp_missing(data: ConfigData) -> list[Finding]:
    if data.copp_service_policy_set:
        return []
    return [
        Finding(
            rule_id="R048",
            severity="high",
            message=(
                "Control Plane Policing (CoPP) tanımlı değil. CPU'yu hedef alan DoS "
                "saldırılarına karşı koruma yok."
            ),
            context="control-plane",
        )
    ]


def _rule_rsa_modulus_weak(data: ConfigData) -> list[Finding]:
    if data.rsa_modulus is None:
        return []
    if data.rsa_modulus >= 2048:
        return []
    return [
        Finding(
            rule_id="R049",
            severity="high",
            message=(
                f"RSA anahtar uzunluğu {data.rsa_modulus} bit. En az 2048 bit olmalı."
            ),
            context=f"crypto key generate rsa modulus {data.rsa_modulus}",
        )
    ]


def _rule_ospf_area_authentication_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    interface_auth_areas: dict[int, set[str]] = {}
    for intf in data.interfaces:
        if (
            intf.ospf_authentication
            and intf.ospf_process_id is not None
            and intf.ospf_area is not None
        ):
            interface_auth_areas.setdefault(intf.ospf_process_id, set()).add(
                intf.ospf_area
            )
    for process_id, process in data.ospf_processes.items():
        unauth_areas = (
            process.areas
            - process.areas_with_auth
            - interface_auth_areas.get(process_id, set())
        )
        for area in sorted(unauth_areas):
            findings.append(
                Finding(
                    rule_id="R050",
                    severity="critical",
                    message=(
                        f"OSPF process {process_id} area {area} için authentication "
                        f"tanımlı değil; kimlik doğrulanmamış komşuluk ve link-state "
                        f"bütünlüğü riski."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
    return findings


def _rule_bgp_neighbor_missing_password(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None:
            continue
        if not neighbor.password_set:
            findings.append(
                Finding(
                    rule_id="R051",
                    severity="high",
                    message=(
                        f"BGP neighbor {neighbor.neighbor_ip} için MD5 password "
                        f"(authentication) tanımlı değil."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip}",
                )
            )
    return findings


def _rule_ospf_passive_default_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for process_id, process in data.ospf_processes.items():
        if not process.passive_default:
            findings.append(
                Finding(
                    rule_id="R053",
                    severity="medium",
                    message=(
                        f"OSPF process {process_id} altında `passive-interface default` "
                        f"tanımlı değil. Routing güncellemeleri kullanıcı portlarına sızabilir."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
    return findings


def _rule_ospf_router_id_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for process_id, process in data.ospf_processes.items():
        if not process.explicit_router_id:
            findings.append(
                Finding(
                    rule_id="R054",
                    severity="medium",
                    message=(
                        f"OSPF process {process_id} için `router-id` explicit olarak "
                        f"tanımlanmamış. Beklenmeyen yeniden seçim adjacency'leri sıfırlayabilir."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
    return findings


def _rule_ospf_log_adjacency_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for process_id, process in data.ospf_processes.items():
        if not process.log_adjacency_changes:
            findings.append(
                Finding(
                    rule_id="R055",
                    severity="low",
                    message=(
                        f"OSPF process {process_id} için `log-adjacency-changes` tanımlı "
                        f"değil. Komşu durum değişiklikleri loglanmıyor."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
    return findings


def _rule_ospf_auto_cost_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for process_id, process in data.ospf_processes.items():
        bw = process.auto_cost_reference_bandwidth
        if bw is None:
            findings.append(
                Finding(
                    rule_id="R056",
                    severity="low",
                    message=(
                        f"OSPF process {process_id} için `auto-cost reference-bandwidth` "
                        f"tanımlı değil (varsayılan 100 Mbps). 1G ve üzeri linkler aynı "
                        f"maliyete sahip olur."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
        elif bw < 1000:
            findings.append(
                Finding(
                    rule_id="R056",
                    severity="low",
                    message=(
                        f"OSPF process {process_id} `auto-cost reference-bandwidth` "
                        f"{bw} Mbps. Modern ağlarda en az 10000 (10G) önerilir."
                    ),
                    context=f"router ospf {process_id}",
                )
            )
    return findings


def _rule_bgp_neighbor_max_prefix_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None:
            continue
        is_ebgp = (
            data.bgp_local_as is not None
            and neighbor.remote_as != data.bgp_local_as
        )
        severity = "high" if is_ebgp else "medium"
        if not neighbor.max_prefix_set:
            findings.append(
                Finding(
                    rule_id="R057",
                    severity=severity,
                    message=(
                        f"BGP neighbor {neighbor.neighbor_ip} için `maximum-prefix` "
                        f"tanımlı değil. Komşudan gelen aşırı prefix RIB/FIB'i tüketebilir."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip}",
                )
            )
    return findings


def _rule_bgp_neighbor_ttl_security_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None or data.bgp_local_as is None:
            continue
        if neighbor.remote_as == data.bgp_local_as:
            continue
        if not neighbor.ttl_security_set:
            findings.append(
                Finding(
                    rule_id="R058",
                    severity="high",
                    message=(
                        f"eBGP neighbor {neighbor.neighbor_ip} için `ttl-security hops` "
                        f"(GTSM) tanımlı değil. Uzak hop spoof saldırılarına açık."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip}",
                )
            )
    return findings


def _rule_bgp_log_neighbor_changes_missing(data: ConfigData) -> list[Finding]:
    if data.bgp_local_as is None:
        return []
    if data.bgp_log_neighbor_changes:
        return []
    return [
        Finding(
            rule_id="R059",
            severity="low",
            message=(
                f"BGP process AS {data.bgp_local_as} altında `bgp log-neighbor-changes` "
                f"tanımlı değil. Peer state değişiklikleri loglanmıyor."
            ),
            context=f"router bgp {data.bgp_local_as}",
        )
    ]


def _rule_bgp_neighbor_description_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None:
            continue
        if not neighbor.description_set:
            findings.append(
                Finding(
                    rule_id="R060",
                    severity="low",
                    message=(
                        f"BGP neighbor {neighbor.neighbor_ip} için `description` tanımlı "
                        f"değil. Operasyonel takip ve troubleshooting zorlaşır."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip}",
                )
            )
    return findings


def _rule_ibgp_update_source_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    if data.bgp_local_as is None:
        return findings
    for neighbor in data.bgp_neighbors.values():
        if neighbor.remote_as is None:
            continue
        if neighbor.remote_as != data.bgp_local_as:
            continue
        if not neighbor.update_source_set:
            findings.append(
                Finding(
                    rule_id="R061",
                    severity="medium",
                    message=(
                        f"iBGP neighbor {neighbor.neighbor_ip} için `update-source` "
                        f"(genelde Loopback) tanımlı değil. Tek link arızası peering'i bozar."
                    ),
                    context=f"neighbor {neighbor.neighbor_ip}",
                )
            )
    return findings


def _rule_urpf_missing(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for intf in data.interfaces:
        if not intf.has_ip_address:
            continue
        if intf.shutdown:
            continue
        name_lower = intf.name.lower()
        if name_lower.startswith("loopback") or name_lower.startswith("lo"):
            continue
        if intf.urpf_enabled:
            continue
        findings.append(
            Finding(
                rule_id="R052",
                severity="medium",
                message=(
                    f"{intf.name} L3 interface'inde uRPF "
                    f"(`ip verify unicast source reachable-via rx`) tanımlı değil."
                ),
                context=f"interface {intf.name}",
            )
        )
    return findings


def _rule_ntp_authentication_missing(data: ConfigData) -> list[Finding]:
    if not data.has_ntp_server:
        return []
    if data.ntp_authenticate_enabled or data.ntp_auth_keys_configured:
        return []
    return [
        Finding(
            rule_id="R069",
            severity="medium",
            message=(
                "NTP sunucusu tanımlı ancak NTP kimlik doğrulaması "
                "(`ntp authenticate`, `ntp authentication-key` veya `ntp server ... key`) yok."
            ),
            context="ntp server",
        )
    ]


def _rule_logging_source_interface_missing(data: ConfigData) -> list[Finding]:
    if not data.has_logging_host:
        return []
    if data.logging_source_interface_set:
        return []
    return [
        Finding(
            rule_id="R070",
            severity="medium",
            message=(
                "Uzak syslog kullanılıyor ancak `logging source-interface` tanımlı değil. "
                "Kaynak arayüz belirsiz kalır; güvenlik ve filtreleme zorlaşır."
            ),
            context="logging host",
        )
    ]


def _rule_tacacs_source_interface_missing(data: ConfigData) -> list[Finding]:
    if not data.aaa_new_model_enabled or not data.tacacs_server_configured:
        return []
    if data.ip_tacacs_source_interface_set:
        return []
    return [
        Finding(
            rule_id="R071",
            severity="high",
            message=(
                "TACACS+ sunucusu tanımlı ancak `ip tacacs source-interface` yok. "
                "Kaynak IP tutarsız olabilir; sunucu tarafı ACL ve denetim zayıflar."
            ),
            context="tacacs-server",
        )
    ]


def _rule_radius_source_interface_missing(data: ConfigData) -> list[Finding]:
    if not data.aaa_new_model_enabled or not data.radius_server_configured:
        return []
    if data.ip_radius_source_interface_set:
        return []
    return [
        Finding(
            rule_id="R072",
            severity="high",
            message=(
                "RADIUS sunucusu tanımlı ancak `ip radius source-interface` yok. "
                "Kaynak IP tutarsız olabilir; CoA ve güvenlik politikaları zorlaşır."
            ),
            context="radius-server",
        )
    ]


def _rule_username_password_not_secret(data: ConfigData) -> list[Finding]:
    findings: list[Finding] = []
    for raw in data.username_password_lines:
        findings.append(
            Finding(
                rule_id="R073",
                severity="high",
                message=(
                    "Yerel kullanıcı `password` ile tanımlı. Kurumsal ortamda "
                    "`username ... secret` (hash) veya AAA ile merkezi kimlik doğrulama kullanın."
                ),
                context=raw,
            )
        )
    return findings


def _rule_service_timestamps_log_msec_missing(data: ConfigData) -> list[Finding]:
    if not data.has_logging_host:
        return []
    if data.service_timestamps_log_msec:
        return []
    return [
        Finding(
            rule_id="R074",
            severity="low",
            message=(
                "`service timestamps log datetime msec` tanımlı değil. "
                "Milisaniye damgalı loglar olay korelasyonu ve adli analiz için önerilir."
            ),
            context="global configuration",
        )
    ]


def _rule_ip_cef_disabled(data: ConfigData) -> list[Finding]:
    if not data.ip_cef_disabled:
        return []
    return [
        Finding(
            rule_id="R075",
            severity="medium",
            message=(
                "`no ip cef` etkin. CEF kapalı iken forwarding performansı ve bazı "
                "güvenlik özellikleri (uRPF vb.) beklenenden farklı davranabilir; üretimde "
                "sadece troubleshooting amaçlı olmalı."
            ),
            context="no ip cef",
        )
    ]


def _rule_snmp_contact_missing(data: ConfigData) -> list[Finding]:
    if not data.snmp_communities and not data.snmpv3_configured:
        return []
    if data.snmp_contact_set:
        return []
    return [
        Finding(
            rule_id="R076",
            severity="low",
            message=(
                "SNMP kullanılıyor ancak `snmp-server contact` bilgisi tanımlı değil. "
                "NMS ve operasyon ekipleri için acil durum iletişim bilgisi önerilir."
            ),
            context="snmp-server",
        )
    ]


def _rule_snmp_location_missing(data: ConfigData) -> list[Finding]:
    if not data.snmp_communities and not data.snmpv3_configured:
        return []
    if data.snmp_location_set:
        return []
    return [
        Finding(
            rule_id="R077",
            severity="low",
            message=(
                "`snmp-server location` tanımlı değil. Fiziksel konum bilgisi "
                "envanter ve olay müdahalesi için önerilir."
            ),
            context="snmp-server",
        )
    ]


def _rule_crypto_pki_missing_domain_name(data: ConfigData) -> list[Finding]:
    if not data.crypto_pki_trustpoint_seen:
        return []
    if data.ip_domain_name_set:
        return []
    return [
        Finding(
            rule_id="R078",
            severity="medium",
            message=(
                "PKI trustpoint tanımlı ancak `ip domain-name` yok. "
                "Sertifika enrollment ve CRL/SCEP için FQDN genelde gereklidir."
            ),
            context="crypto pki trustpoint",
        )
    ]


def _rule_archive_log_config_missing(data: ConfigData) -> list[Finding]:
    if not data.archive_enabled:
        return []
    if data.archive_log_config_enabled:
        return []
    return [
        Finding(
            rule_id="R079",
            severity="info",
            message=(
                "`archive` etkin ancak `log config` (konfigürasyon değişiklik günlüğü) "
                "tanımlı değil (operasyonel/denetim önerisi; güvenlik bulgusu değildir). "
                "Denetim ve geri alma için `archive` altında `log config` önerilir."
            ),
            context="archive",
        )
    ]


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
        _rule_snmpv3_missing,
        _rule_snmp_community_no_acl,
        _rule_copp_missing,
        _rule_rsa_modulus_weak,
        _rule_ospf_area_authentication_missing,
        _rule_bgp_neighbor_missing_password,
        _rule_urpf_missing,
        _rule_ospf_passive_default_missing,
        _rule_ospf_router_id_missing,
        _rule_ospf_log_adjacency_missing,
        _rule_ospf_auto_cost_missing,
        _rule_bgp_neighbor_max_prefix_missing,
        _rule_bgp_neighbor_ttl_security_missing,
        _rule_bgp_log_neighbor_changes_missing,
        _rule_bgp_neighbor_description_missing,
        _rule_ibgp_update_source_missing,
        _rule_ntp_authentication_missing,
        _rule_logging_source_interface_missing,
        _rule_tacacs_source_interface_missing,
        _rule_radius_source_interface_missing,
        _rule_username_password_not_secret,
        _rule_service_timestamps_log_msec_missing,
        _rule_ip_cef_disabled,
        _rule_snmp_contact_missing,
        _rule_snmp_location_missing,
        _rule_crypto_pki_missing_domain_name,
        _rule_archive_log_config_missing,
    ):
        findings.extend(rule(data))
    for finding in findings:
        finding.category = RULE_CATEGORIES.get(finding.rule_id, "general")
    return findings
