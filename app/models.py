from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    description: str | None = None
    shutdown: bool = False
    switchport_mode: str | None = None
    access_vlan: int | None = None
    trunk_vlans: list[int] = field(default_factory=list)
    ospf_process_id: int | None = None
    ospf_area: str | None = None
    trunk_native_vlan: int | None = None
    port_security_enabled: bool = False
    bpduguard_enabled: bool = False
    cdp_disabled: bool = False
    proxy_arp_disabled: bool = False
    icmp_redirects_disabled: bool = False
    nonegotiate_set: bool = False
    storm_control_enabled: bool = False
    has_ip_address: bool = False
    urpf_enabled: bool = False
    ospf_authentication: bool = False


@dataclass
class AccessListEntry:
    acl_name: str
    action: str
    protocol: str
    src: str
    dst: str
    raw_line: str


@dataclass
class OspfProcess:
    process_id: int
    areas: set[str] = field(default_factory=set)
    areas_with_auth: set[str] = field(default_factory=set)
    passive_default: bool = False
    explicit_router_id: bool = False
    log_adjacency_changes: bool = False
    auto_cost_reference_bandwidth: int | None = None


@dataclass
class BgpNeighbor:
    neighbor_ip: str
    remote_as: int | None = None
    route_maps: dict[str, str] = field(default_factory=dict)
    password_set: bool = False
    max_prefix_set: bool = False
    ttl_security_set: bool = False
    description_set: bool = False
    update_source_set: bool = False
    update_source_interface: str | None = None


@dataclass
class SnmpCommunity:
    name: str
    permission: str | None = None
    raw_line: str = ""
    acl_name: str | None = None


@dataclass
class ConfigData:
    vlans: set[int] = field(default_factory=set)
    interfaces: list[Interface] = field(default_factory=list)
    acls: list[AccessListEntry] = field(default_factory=list)
    ospf_processes: dict[int, OspfProcess] = field(default_factory=dict)
    bgp_neighbors: dict[str, BgpNeighbor] = field(default_factory=dict)
    ssh_version: int | None = None
    console_exec_timeout_set: bool = False
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    service_password_encryption_enabled: bool = False
    enable_secret_set: bool = False
    vty_has_telnet_transport: bool = False
    ip_http_server_enabled: bool = False
    ip_http_secure_server_enabled: bool = False
    aaa_new_model_enabled: bool = False
    has_logging_host: bool = False
    has_ntp_server: bool = False
    has_banner_motd: bool = False
    has_login_block_for: bool = False
    ip_domain_lookup_disabled: bool = False
    service_finger_enabled: bool = False
    ip_source_route_disabled: bool = False
    service_pad_disabled: bool = False
    cdp_run_disabled: bool = False
    has_clock_timezone: bool = False
    bpduguard_default_enabled: bool = False
    vty_has_access_class: bool = False
    has_service_tcp_keepalives: bool = False
    enable_password_cleartext: bool = False
    dhcp_snooping_enabled: bool = False
    arp_inspection_enabled: bool = False
    vty_exec_timeout_set: bool = False
    aux_no_exec_set: bool = False
    aux_section_seen: bool = False
    spanning_tree_mode: str | None = None
    has_logging_buffered: bool = False
    ssh_timeout_set: bool = False
    ssh_auth_retries_set: bool = False
    archive_enabled: bool = False
    snmpv3_configured: bool = False
    copp_service_policy_set: bool = False
    rsa_modulus: int | None = None
    bgp_local_as: int | None = None
    bgp_router_id_set: bool = False
    bgp_log_neighbor_changes: bool = False
    ntp_authenticate_enabled: bool = False
    ntp_auth_keys_configured: bool = False
    logging_source_interface_set: bool = False
    tacacs_server_configured: bool = False
    radius_server_configured: bool = False
    ip_tacacs_source_interface_set: bool = False
    ip_radius_source_interface_set: bool = False
    username_password_lines: list[str] = field(default_factory=list)
    service_timestamps_log_msec: bool = False
    ip_cef_disabled: bool = False
    snmp_contact_set: bool = False
    snmp_location_set: bool = False
    crypto_pki_trustpoint_seen: bool = False
    ip_domain_name_set: bool = False
    archive_log_config_enabled: bool = False


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    context: str
    category: str = "general"
    # Aynı kuralın çoklu arayüz/neighbor/satır tekrarları tek satırda birleştirildiğinde
    # diff karşılaştırması ve rapor için sabit kimlik (opsiyonel).
    stable_key: str | None = None
    occurrence_count: int = 1
