import re

from app.models import (
    AccessListEntry,
    BgpNeighbor,
    ConfigData,
    Interface,
    OspfProcess,
    SnmpCommunity,
)


def _parse_vlan_token(token: str) -> list[int]:
    token = token.strip()
    if "-" in token:
        start, end = token.split("-", maxsplit=1)
        if start.isdigit() and end.isdigit():
            return list(range(int(start), int(end) + 1))
        return []
    return [int(token)] if token.isdigit() else []


_IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _line_sets_global_bpduguard_default(line: str) -> bool:
    """
    Global BPDU Guard varsayılanı: tüm PortFast (genelde access) portlara miras alır.
    IOS / IOS-XE sözdizimi varyantlarını kapsar; 'no ...' satırlarını dışlar.
    """
    if not line or line.startswith("!"):
        return False
    if line.lower().startswith("no "):
        return False
    if re.match(
        r"^spanning-tree\s+portfast\s+(?:edge\s+)?bpduguard\s+default\b",
        line,
        flags=re.IGNORECASE,
    ):
        return True
    if re.match(r"^spanning-tree\s+bpduguard\s+default\b", line, flags=re.IGNORECASE):
        return True
    return False


def _apply_global_bpduguard_inheritance(data: ConfigData) -> None:
    """Global 'portfast bpduguard default' etkinse access portlarında bpduguard etkindir."""
    if not data.bpduguard_default_enabled:
        return
    for intf in data.interfaces:
        if intf.switchport_mode == "access":
            intf.bpduguard_enabled = True


def _consume_acl_endpoint(pieces: list[str], idx: int) -> tuple[str, int]:
    if idx >= len(pieces):
        return "", idx
    first = pieces[idx]
    lower = first.lower()
    if lower == "any":
        return "any", idx + 1
    if lower == "host" and idx + 1 < len(pieces):
        return f"host {pieces[idx + 1]}", idx + 2
    if _IPV4_RE.match(first) and idx + 1 < len(pieces) and _IPV4_RE.match(pieces[idx + 1]):
        return f"{first} {pieces[idx + 1]}", idx + 2
    return first, idx + 1


def _parse_acl_src_dst(pieces: list[str]) -> tuple[str, str]:
    src, next_idx = _consume_acl_endpoint(pieces, 0)
    dst, _ = _consume_acl_endpoint(pieces, next_idx)
    return src, dst


def parse_cisco_ios_config(text: str) -> ConfigData:
    data = ConfigData()
    current_interface: Interface | None = None
    current_ospf_process: int | None = None
    in_bgp_section = False
    in_console_line = False
    in_vty_line = False
    in_aux_line = False
    in_control_plane = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        vlan_match = re.match(r"^vlan\s+(\d+)$", line, flags=re.IGNORECASE)
        if vlan_match:
            data.vlans.add(int(vlan_match.group(1)))
            continue

        ssh_version_match = re.match(
            r"^ip\s+ssh\s+version\s+(\d+)$", line, flags=re.IGNORECASE
        )
        if ssh_version_match:
            data.ssh_version = int(ssh_version_match.group(1))
            continue

        if re.match(r"^service\s+password-encryption$", line, flags=re.IGNORECASE):
            data.service_password_encryption_enabled = True
            continue

        if re.match(r"^enable\s+secret\s+.+$", line, flags=re.IGNORECASE):
            data.enable_secret_set = True
            continue

        if re.match(
            r"^enable\s+password\s+(?:0\s+)?\S+$", line, flags=re.IGNORECASE
        ) and not re.match(
            r"^enable\s+password\s+[5-9]\s+\S+$", line, flags=re.IGNORECASE
        ) and not re.match(
            r"^enable\s+password\s+7\s+\S+$", line, flags=re.IGNORECASE
        ):
            data.enable_password_cleartext = True
            continue

        if re.match(r"^ip\s+dhcp\s+snooping$", line, flags=re.IGNORECASE):
            data.dhcp_snooping_enabled = True
            continue

        if re.match(r"^ip\s+arp\s+inspection\s+vlan\b", line, flags=re.IGNORECASE):
            data.arp_inspection_enabled = True
            continue

        spanning_tree_mode_match = re.match(
            r"^spanning-tree\s+mode\s+(\S+)$", line, flags=re.IGNORECASE
        )
        if spanning_tree_mode_match:
            data.spanning_tree_mode = spanning_tree_mode_match.group(1).lower()
            continue

        if re.match(r"^logging\s+buffered\b", line, flags=re.IGNORECASE):
            data.has_logging_buffered = True
            continue

        if re.match(r"^ip\s+ssh\s+time-out\s+\d+$", line, flags=re.IGNORECASE):
            data.ssh_timeout_set = True
            continue

        if re.match(
            r"^ip\s+ssh\s+authentication-retries\s+\d+$", line, flags=re.IGNORECASE
        ):
            data.ssh_auth_retries_set = True
            continue

        if re.match(r"^archive$", line, flags=re.IGNORECASE):
            data.archive_enabled = True
            continue

        if re.match(r"^ip\s+http\s+server$", line, flags=re.IGNORECASE):
            data.ip_http_server_enabled = True
            continue

        if re.match(r"^no\s+ip\s+http\s+server$", line, flags=re.IGNORECASE):
            data.ip_http_server_enabled = False
            continue

        if re.match(r"^ip\s+http\s+secure-server$", line, flags=re.IGNORECASE):
            data.ip_http_secure_server_enabled = True
            continue

        if re.match(r"^aaa\s+new-model$", line, flags=re.IGNORECASE):
            data.aaa_new_model_enabled = True
            continue

        if re.match(r"^logging\s+host\s+\S+", line, flags=re.IGNORECASE) or re.match(
            r"^logging\s+\d+\.\d+\.\d+\.\d+$", line, flags=re.IGNORECASE
        ):
            data.has_logging_host = True
            continue

        if re.match(r"^logging\s+source-interface\s+\S+", line, flags=re.IGNORECASE):
            data.logging_source_interface_set = True
            continue

        if re.match(r"^ntp\s+server\s+\S+", line, flags=re.IGNORECASE):
            data.has_ntp_server = True
            if re.search(r"\bkey\s+\d+\b", line, flags=re.IGNORECASE):
                data.ntp_auth_keys_configured = True
            continue

        if re.match(r"^ntp\s+authentication-key\s+\d+", line, flags=re.IGNORECASE):
            data.ntp_auth_keys_configured = True
            continue

        if re.match(r"^ntp\s+trusted-key\b", line, flags=re.IGNORECASE):
            data.ntp_auth_keys_configured = True
            continue

        if re.match(r"^ntp\s+authenticate\b", line, flags=re.IGNORECASE):
            data.ntp_authenticate_enabled = True
            continue

        if re.match(r"^tacacs-server\s+host\b", line, flags=re.IGNORECASE) or re.match(
            r"^tacacs\s+server\s+\S+", line, flags=re.IGNORECASE
        ):
            data.tacacs_server_configured = True
            continue

        if re.match(r"^radius-server\s+host\b", line, flags=re.IGNORECASE) or re.match(
            r"^radius\s+server\s+\S+", line, flags=re.IGNORECASE
        ):
            data.radius_server_configured = True
            continue

        if re.match(r"^ip\s+tacacs\s+source-interface\s+\S+", line, flags=re.IGNORECASE):
            data.ip_tacacs_source_interface_set = True
            continue

        if re.match(r"^ip\s+radius\s+source-interface\s+\S+", line, flags=re.IGNORECASE):
            data.ip_radius_source_interface_set = True
            continue

        if re.match(r"^username\s+\S+\s+password\b", line, flags=re.IGNORECASE):
            data.username_password_lines.append(line)
            continue

        if re.match(
            r"^service\s+timestamps\s+log\s+datetime\s+msec",
            line,
            flags=re.IGNORECASE,
        ):
            data.service_timestamps_log_msec = True
            continue

        if re.match(r"^no\s+ip\s+cef\b", line, flags=re.IGNORECASE):
            data.ip_cef_disabled = True
            continue

        if re.match(r"^snmp-server\s+contact\b", line, flags=re.IGNORECASE):
            data.snmp_contact_set = True
            continue

        if re.match(r"^snmp-server\s+location\b", line, flags=re.IGNORECASE):
            data.snmp_location_set = True
            continue

        if re.match(
            r"^crypto\s+(pki|ca)\s+trustpoint\s+\S+", line, flags=re.IGNORECASE
        ):
            data.crypto_pki_trustpoint_seen = True
            continue

        if re.match(r"^ip\s+domain-name\s+\S+", line, flags=re.IGNORECASE):
            data.ip_domain_name_set = True
            continue

        if re.match(r"^log\s+config\b", line, flags=re.IGNORECASE):
            data.archive_log_config_enabled = True
            continue

        if re.match(r"^banner\s+motd\b", line, flags=re.IGNORECASE):
            data.has_banner_motd = True
            continue

        if re.match(r"^login\s+block-for\s+\d+", line, flags=re.IGNORECASE):
            data.has_login_block_for = True
            continue

        if re.match(r"^no\s+ip\s+domain[- ]lookup$", line, flags=re.IGNORECASE):
            data.ip_domain_lookup_disabled = True
            continue

        if re.match(r"^(service\s+finger|ip\s+finger)$", line, flags=re.IGNORECASE):
            data.service_finger_enabled = True
            continue

        if re.match(r"^no\s+ip\s+source-route$", line, flags=re.IGNORECASE):
            data.ip_source_route_disabled = True
            continue

        if re.match(r"^no\s+service\s+pad$", line, flags=re.IGNORECASE):
            data.service_pad_disabled = True
            continue

        if re.match(r"^no\s+cdp\s+run$", line, flags=re.IGNORECASE):
            data.cdp_run_disabled = True
            continue

        if re.match(r"^clock\s+timezone\s+\S+", line, flags=re.IGNORECASE):
            data.has_clock_timezone = True
            continue

        if re.match(r"^no\s+service\s+password-recovery$", line, flags=re.IGNORECASE):
            data.service_password_recovery_disabled = True
            continue

        if re.match(r"^no\s+vstack$", line, flags=re.IGNORECASE):
            data.vstack_disabled = True
            continue

        if re.match(r"^ip\s+options\s+(?:selective-)?drop$", line, flags=re.IGNORECASE):
            data.ip_options_drop_enabled = True
            continue

        if re.match(r"^router\s+eigrp\s+\d+$", line, flags=re.IGNORECASE):
            data.eigrp_enabled = True
            continue

        if re.match(r"^no\s+logging\s+console$", line, flags=re.IGNORECASE):
            data.logging_console_disabled = True
            continue

        if re.match(r"^ip\s+scp\s+server\s+enable$", line, flags=re.IGNORECASE):
            data.scp_server_enabled = True
            continue

        if re.match(r"^snmp-server\s+view\s+\S+", line, flags=re.IGNORECASE):
            data.snmp_views_configured = True
            continue

        if re.match(r"^configuration\s+mode\s+exclusive\s+auto$", line, flags=re.IGNORECASE):
            data.configuration_mode_exclusive_auto = True
            continue

        if re.match(r"^secure\s+boot-image$", line, flags=re.IGNORECASE):
            data.secure_boot_image_enabled = True
            continue

        if re.match(r"^secure\s+boot-config$", line, flags=re.IGNORECASE):
            data.secure_boot_config_enabled = True
            continue

        if re.match(r"^memory\s+free\s+low-watermark\b", line, flags=re.IGNORECASE):
            data.memory_free_low_watermark_set = True
            continue

        if re.match(r"^memory\s+reserve\s+critical\b", line, flags=re.IGNORECASE):
            data.memory_reserve_critical_set = True
            continue

        if re.match(r"^snmp-server\s+enable\s+traps\s+cpu\b", line, flags=re.IGNORECASE) or re.match(r"^process\s+cpu\s+threshold\b", line, flags=re.IGNORECASE):
            data.cpu_threshold_notification_enabled = True
            continue

        if re.match(r"^memory\s+reserve\s+console\s+\d+", line, flags=re.IGNORECASE):
            data.memory_reserve_console_set = True
            continue

        if re.match(r"^ip\s+icmp\s+rate-limit\s+unreachable\s+\d+", line, flags=re.IGNORECASE):
            data.ip_icmp_rate_limit_unreachable_set = True
            continue

        if re.match(r"^no\s+service\s+tcp-small-servers$", line, flags=re.IGNORECASE):
            data.no_service_tcp_small_servers = True
            continue

        if re.match(r"^no\s+service\s+udp-small-servers$", line, flags=re.IGNORECASE):
            data.no_service_udp_small_servers = True
            continue

        if re.match(r"^no\s+ip\s+bootp\s+server$", line, flags=re.IGNORECASE) or re.match(r"^ip\s+dhcp\s+bootp\s+ignore$", line, flags=re.IGNORECASE):
            data.bootp_server_disabled = True
            continue

        if re.match(r"^ipv6\s+unicast-routing$", line, flags=re.IGNORECASE):
            data.ipv6_unicast_routing_enabled = True
            continue

        if re.match(r"^aaa\s+authorization\s+commands\b", line, flags=re.IGNORECASE):
            data.aaa_authorization_commands = True
            continue

        if re.match(r"^aaa\s+accounting\s+commands\b", line, flags=re.IGNORECASE):
            data.aaa_accounting_commands = True
            continue

        if re.match(r"^boot\s+system\s+", line, flags=re.IGNORECASE):
            data.boot_system_configured = True
            continue

        if re.match(r"^ip\s+http\s+authentication\s+aaa$", line, flags=re.IGNORECASE):
            data.ip_http_authentication_aaa_enabled = True
            continue

        if re.match(r"^(?:distribute-list|neighbor\s+\S+\s+distribute-list)\b", line, flags=re.IGNORECASE):
            data.has_distribute_list = True
            continue

        if _line_sets_global_bpduguard_default(line):
            data.bpduguard_default_enabled = True
            continue

        if re.match(
            r"^service\s+tcp-keepalives-(in|out)$", line, flags=re.IGNORECASE
        ):
            data.has_service_tcp_keepalives = True
            continue

        snmp_community_match = re.match(
            r"^snmp-server\s+community\s+(\S+)(.*)$",
            line,
            flags=re.IGNORECASE,
        )
        if snmp_community_match:
            name = snmp_community_match.group(1)
            rest_tokens = snmp_community_match.group(2).split()
            permission: str | None = None
            acl_name: str | None = None
            i = 0
            while i < len(rest_tokens):
                token = rest_tokens[i]
                if token.upper() in {"RO", "RW"}:
                    permission = token.lower()
                    i += 1
                elif token.lower() == "view" and i + 1 < len(rest_tokens):
                    i += 2
                elif token.lower() == "ipv6" and i + 1 < len(rest_tokens):
                    i += 2
                else:
                    acl_name = token
                    i += 1
            data.snmp_communities.append(
                SnmpCommunity(
                    name=name,
                    permission=permission,
                    raw_line=line,
                    acl_name=acl_name,
                )
            )
            continue

        if re.match(
            r"^snmp-server\s+(?:user\s+\S+(?:\s+\S+)?|group\s+\S+)\s+v3\b",
            line,
            flags=re.IGNORECASE,
        ):
            data.snmpv3_configured = True
            if re.search(r"\b(?:auth|noauth)\b", line, flags=re.IGNORECASE) and not re.search(r"\bpriv\b", line, flags=re.IGNORECASE):
                data.snmpv3_has_non_priv = True
            continue

        rsa_match = re.match(
            r"^crypto\s+key\s+generate\s+rsa\b", line, flags=re.IGNORECASE
        )
        if rsa_match:
            modulus_match = re.search(
                r"\bmodulus\s+(\d+)\b", line, flags=re.IGNORECASE
            )
            if modulus_match is not None:
                data.rsa_modulus = int(modulus_match.group(1))
            continue

        line_console_match = re.match(
            r"^line\s+con(?:sole)?\s+\d+$", line, flags=re.IGNORECASE
        )
        if line_console_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = True
            in_vty_line = False
            in_aux_line = False
            in_control_plane = False
            continue

        line_vty_match = re.match(r"^line\s+vty\b.*$", line, flags=re.IGNORECASE)
        if line_vty_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = True
            in_aux_line = False
            in_control_plane = False
            continue

        line_aux_match = re.match(r"^line\s+aux\b.*$", line, flags=re.IGNORECASE)
        if line_aux_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = True
            in_control_plane = False
            data.aux_section_seen = True
            continue

        if re.match(r"^control-plane$", line, flags=re.IGNORECASE):
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
            in_control_plane = True
            continue

        intf_match = re.match(r"^interface\s+(\S+)$", line, flags=re.IGNORECASE)
        if intf_match:
            current_interface = Interface(name=intf_match.group(1))
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
            in_control_plane = False
            data.interfaces.append(current_interface)
            continue

        ospf_match = re.match(r"^router\s+ospf\s+(\d+)$", line, flags=re.IGNORECASE)
        if ospf_match:
            current_interface = None
            current_ospf_process = int(ospf_match.group(1))
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
            in_control_plane = False
            data.ospf_processes.setdefault(
                current_ospf_process,
                OspfProcess(process_id=current_ospf_process),
            )
            continue

        bgp_match = re.match(r"^router\s+bgp\s+(\d+)$", line, flags=re.IGNORECASE)
        if bgp_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = True
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
            in_control_plane = False
            data.bgp_local_as = int(bgp_match.group(1))
            continue

        acl_match = re.match(
            r"^access-list\s+(\S+)\s+(permit|deny)\s+(\S+)\s+(.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if acl_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
            in_control_plane = False
            acl_name, action, protocol, remainder = acl_match.groups()
            pieces = remainder.split()
            src, dst = _parse_acl_src_dst(pieces)
            data.acls.append(
                AccessListEntry(
                    acl_name=acl_name,
                    action=action.lower(),
                    protocol=protocol.lower(),
                    src=src.lower(),
                    dst=dst.lower(),
                    raw_line=line,
                )
            )
            continue

        console_timeout_match = re.match(
            r"^exec-timeout\s+(\d+)(?:\s+(\d+))?$", line, flags=re.IGNORECASE
        )
        if in_console_line and console_timeout_match:
            minutes = int(console_timeout_match.group(1))
            seconds = int(console_timeout_match.group(2) or 0)
            if minutes > 0 or seconds > 0:
                data.console_exec_timeout_set = True
            continue

        if in_console_line and re.match(
            r"^access-class\s+\S+\s+(in|out)$", line, flags=re.IGNORECASE
        ):
            data.console_access_class_configured = True
            continue

        if in_vty_line and re.match(
            r"^transport\s+input\s+.*\btelnet\b.*$", line, flags=re.IGNORECASE
        ):
            data.vty_has_telnet_transport = True
            continue

        if in_vty_line and re.match(
            r"^access-class\s+\S+\s+(in|out)$", line, flags=re.IGNORECASE
        ):
            data.vty_has_access_class = True
            continue

        vty_timeout_match = re.match(
            r"^exec-timeout\s+(\d+)(?:\s+(\d+))?$", line, flags=re.IGNORECASE
        )
        if in_vty_line and vty_timeout_match:
            minutes = int(vty_timeout_match.group(1))
            seconds = int(vty_timeout_match.group(2) or 0)
            if minutes > 0 or seconds > 0:
                data.vty_exec_timeout_set = True
            continue

        if in_aux_line and re.match(r"^no\s+exec$", line, flags=re.IGNORECASE):
            data.aux_no_exec_set = True
            continue

        if in_aux_line and re.match(
            r"^access-class\s+\S+\s+(in|out)$", line, flags=re.IGNORECASE
        ):
            data.aux_access_class_configured = True
            continue

        if in_control_plane and re.match(
            r"^service-policy\s+input\s+\S+$", line, flags=re.IGNORECASE
        ):
            data.copp_service_policy_set = True
            continue

        ospf_network_match = re.match(
            r"^network\s+\S+\s+\S+\s+area\s+(\S+)$",
            line,
            flags=re.IGNORECASE,
        )
        if current_ospf_process is not None and ospf_network_match:
            area_id = ospf_network_match.group(1)
            data.ospf_processes[current_ospf_process].areas.add(area_id)
            continue

        ospf_area_auth_match = re.match(
            r"^area\s+(\S+)\s+authentication(?:\s+message-digest)?$",
            line,
            flags=re.IGNORECASE,
        )
        if current_ospf_process is not None and ospf_area_auth_match:
            area_id = ospf_area_auth_match.group(1)
            process = data.ospf_processes.setdefault(
                current_ospf_process,
                OspfProcess(process_id=current_ospf_process),
            )
            process.areas_with_auth.add(area_id)
            continue

        if current_ospf_process is not None and re.match(
            r"^passive-interface\s+default$", line, flags=re.IGNORECASE
        ):
            data.ospf_processes[current_ospf_process].passive_default = True
            continue

        if current_ospf_process is not None and re.match(
            r"^router-id\s+\S+$", line, flags=re.IGNORECASE
        ):
            data.ospf_processes[current_ospf_process].explicit_router_id = True
            continue

        if current_ospf_process is not None and re.match(
            r"^log-adjacency-changes(?:\s+detail)?$", line, flags=re.IGNORECASE
        ):
            data.ospf_processes[current_ospf_process].log_adjacency_changes = True
            continue

        ospf_auto_cost_match = re.match(
            r"^auto-cost\s+reference-bandwidth\s+(\d+)$",
            line,
            flags=re.IGNORECASE,
        )
        if current_ospf_process is not None and ospf_auto_cost_match:
            data.ospf_processes[current_ospf_process].auto_cost_reference_bandwidth = (
                int(ospf_auto_cost_match.group(1))
            )
            continue

        bgp_neighbor_remote_as_match = re.match(
            r"^neighbor\s+(\S+)\s+remote-as\s+(\d+)$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_remote_as_match:
            neighbor_ip, remote_as = bgp_neighbor_remote_as_match.groups()
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.remote_as = int(remote_as)
            continue

        bgp_neighbor_route_map_match = re.match(
            r"^neighbor\s+(\S+)\s+route-map\s+(\S+)\s+(in|out)$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_route_map_match:
            neighbor_ip, route_map_name, direction = bgp_neighbor_route_map_match.groups()
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.route_maps[direction.lower()] = route_map_name
            continue

        bgp_neighbor_password_match = re.match(
            r"^neighbor\s+(\S+)\s+password\s+\S+",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_password_match:
            neighbor_ip = bgp_neighbor_password_match.group(1)
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.password_set = True
            continue

        if in_bgp_section and re.match(
            r"^bgp\s+router-id\s+\S+$", line, flags=re.IGNORECASE
        ):
            data.bgp_router_id_set = True
            continue

        if in_bgp_section and re.match(
            r"^bgp\s+log-neighbor-changes$", line, flags=re.IGNORECASE
        ):
            data.bgp_log_neighbor_changes = True
            continue

        bgp_neighbor_max_prefix_match = re.match(
            r"^neighbor\s+(\S+)\s+maximum-prefix\s+\d+",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_max_prefix_match:
            neighbor_ip = bgp_neighbor_max_prefix_match.group(1)
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.max_prefix_set = True
            continue

        bgp_neighbor_ttl_match = re.match(
            r"^neighbor\s+(\S+)\s+ttl-security\s+hops\s+\d+$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_ttl_match:
            neighbor_ip = bgp_neighbor_ttl_match.group(1)
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.ttl_security_set = True
            continue

        bgp_neighbor_desc_match = re.match(
            r"^neighbor\s+(\S+)\s+description\s+.+$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_desc_match:
            neighbor_ip = bgp_neighbor_desc_match.group(1)
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.description_set = True
            continue

        bgp_neighbor_update_src_match = re.match(
            r"^neighbor\s+(\S+)\s+update-source\s+(\S+)$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_update_src_match:
            neighbor_ip, src_intf = bgp_neighbor_update_src_match.groups()
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.update_source_set = True
            neighbor.update_source_interface = src_intf
            continue

        bgp_neighbor_filter_match = re.match(
            r"^neighbor\s+(\S+)\s+(?:prefix-list|filter-list)\s+\S+\s+in$",
            line,
            flags=re.IGNORECASE,
        )
        if in_bgp_section and bgp_neighbor_filter_match:
            neighbor_ip = bgp_neighbor_filter_match.group(1)
            neighbor = data.bgp_neighbors.setdefault(
                neighbor_ip, BgpNeighbor(neighbor_ip=neighbor_ip)
            )
            neighbor.prefix_or_filter_list_inbound = True
            continue

        if current_interface is None:
            continue

        if re.match(r"^shutdown$", line, flags=re.IGNORECASE):
            current_interface.shutdown = True
            continue

        desc_match = re.match(r"^description\s+(.+)$", line, flags=re.IGNORECASE)
        if desc_match:
            current_interface.description = desc_match.group(1).strip()
            continue

        intf_ospf_match = re.match(
            r"^ip\s+ospf\s+(\d+)\s+area\s+(\S+)$",
            line,
            flags=re.IGNORECASE,
        )
        if intf_ospf_match:
            process_id, area = intf_ospf_match.groups()
            current_interface.ospf_process_id = int(process_id)
            current_interface.ospf_area = area
            continue

        if re.match(
            r"^ip\s+ospf\s+authentication(?:\s+message-digest)?$",
            line,
            flags=re.IGNORECASE,
        ) or re.match(
            r"^ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+\S+",
            line,
            flags=re.IGNORECASE,
        ) or re.match(
            r"^ip\s+ospf\s+authentication-key\s+\S+",
            line,
            flags=re.IGNORECASE,
        ):
            current_interface.ospf_authentication = True
            continue

        if re.match(r"^ip\s+address\s+\S+\s+\S+", line, flags=re.IGNORECASE):
            current_interface.has_ip_address = True
            continue

        if re.match(
            r"^ip\s+verify\s+unicast\s+source\s+reachable-via\s+(rx|any)\b",
            line,
            flags=re.IGNORECASE,
        ):
            current_interface.urpf_enabled = True
            continue

        if re.match(
            r"^ipv6\s+verify\s+unicast\s+source\s+reachable-via\s+(rx|any)\b",
            line,
            flags=re.IGNORECASE,
        ):
            current_interface.ipv6_urpf_enabled = True
            continue

        mode_match = re.match(
            r"^switchport\s+mode\s+(access|trunk)$",
            line,
            flags=re.IGNORECASE,
        )
        if mode_match:
            current_interface.switchport_mode = mode_match.group(1).lower()
            continue

        access_match = re.match(
            r"^switchport\s+access\s+vlan\s+(\d+)$",
            line,
            flags=re.IGNORECASE,
        )
        if access_match:
            current_interface.access_vlan = int(access_match.group(1))
            continue

        trunk_match = re.match(
            r"^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if trunk_match:
            chunks = trunk_match.group(1).split(",")
            parsed: list[int] = []
            for chunk in chunks:
                parsed.extend(_parse_vlan_token(chunk))
            current_interface.trunk_vlans = sorted(set(parsed))
            continue

        native_vlan_match = re.match(
            r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)$",
            line,
            flags=re.IGNORECASE,
        )
        if native_vlan_match:
            current_interface.trunk_native_vlan = int(native_vlan_match.group(1))
            continue

        if re.match(r"^switchport\s+port-security\b", line, flags=re.IGNORECASE):
            current_interface.port_security_enabled = True
            continue

        if re.match(
            r"^spanning-tree\s+bpduguard\s+enable$", line, flags=re.IGNORECASE
        ):
            current_interface.bpduguard_enabled = True
            continue

        if re.match(r"^no\s+cdp\s+enable$", line, flags=re.IGNORECASE):
            current_interface.cdp_disabled = True
            continue

        if re.match(r"^no\s+ip\s+proxy-arp$", line, flags=re.IGNORECASE):
            current_interface.proxy_arp_disabled = True
            continue

        if re.match(r"^no\s+ip\s+redirects$", line, flags=re.IGNORECASE):
            current_interface.icmp_redirects_disabled = True
            continue

        if re.match(r"^switchport\s+nonegotiate$", line, flags=re.IGNORECASE):
            current_interface.nonegotiate_set = True
            continue

        if re.match(r"^storm-control\b", line, flags=re.IGNORECASE):
            current_interface.storm_control_enabled = True
            continue

        if re.match(r"^no\s+ip\s+directed-broadcast$", line, flags=re.IGNORECASE):
            current_interface.ip_directed_broadcast_disabled = True
            continue

        if re.match(r"^ip\s+verify\s+source\b", line, flags=re.IGNORECASE):
            current_interface.ip_source_guard_enabled = True
            continue

        if re.match(r"^ip\s+authentication\s+mode\s+eigrp\s+\d+\s+md5$", line, flags=re.IGNORECASE):
            current_interface.eigrp_authentication_enabled = True
            continue

        if re.match(r"^(?:standby|vrrp|glbp)\s+\d+\s+ip\s+", line, flags=re.IGNORECASE):
            current_interface.fhrp_enabled = True
            continue

        if re.match(r"^(?:standby|vrrp|glbp)\s+\d+\s+authentication\s+md5\b", line, flags=re.IGNORECASE):
            current_interface.fhrp_authentication_md5 = True
            continue

        if re.match(r"^no\s+ip\s+unreachables$", line, flags=re.IGNORECASE):
            current_interface.ip_unreachables_disabled = True
            continue

        if re.match(r"^no\s+mop\s+enabled$", line, flags=re.IGNORECASE):
            current_interface.mop_disabled = True
            continue

    if not data.bpduguard_default_enabled:
        for raw_line in text.splitlines():
            if _line_sets_global_bpduguard_default(raw_line.strip()):
                data.bpduguard_default_enabled = True
                break

    _apply_global_bpduguard_inheritance(data)

    return data
