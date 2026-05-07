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


def parse_cisco_ios_config(text: str) -> ConfigData:
    data = ConfigData()
    current_interface: Interface | None = None
    current_ospf_process: int | None = None
    in_bgp_section = False
    in_console_line = False
    in_vty_line = False
    in_aux_line = False

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

        if re.match(r"^enable\s+password\s+.+$", line, flags=re.IGNORECASE):
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

        if re.match(r"^ntp\s+server\s+\S+", line, flags=re.IGNORECASE):
            data.has_ntp_server = True
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

        if re.match(
            r"^spanning-tree\s+portfast\s+bpduguard\s+default$",
            line,
            flags=re.IGNORECASE,
        ):
            data.bpduguard_default_enabled = True
            continue

        if re.match(
            r"^service\s+tcp-keepalives-(in|out)$", line, flags=re.IGNORECASE
        ):
            data.has_service_tcp_keepalives = True
            continue

        snmp_community_match = re.match(
            r"^snmp-server\s+community\s+(\S+)(?:\s+(\S+))?.*$",
            line,
            flags=re.IGNORECASE,
        )
        if snmp_community_match:
            name, permission = snmp_community_match.groups()
            data.snmp_communities.append(
                SnmpCommunity(
                    name=name,
                    permission=permission.lower() if permission else None,
                    raw_line=line,
                )
            )
            continue

        line_console_match = re.match(
            r"^line\s+console\s+\d+$", line, flags=re.IGNORECASE
        )
        if line_console_match:
            current_interface = None
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = True
            in_vty_line = False
            in_aux_line = False
            continue

        line_vty_match = re.match(r"^line\s+vty\b.*$", line, flags=re.IGNORECASE)
        if line_vty_match:
            in_console_line = False
            in_vty_line = True
            in_aux_line = False
            continue

        line_aux_match = re.match(r"^line\s+aux\b.*$", line, flags=re.IGNORECASE)
        if line_aux_match:
            in_console_line = False
            in_vty_line = False
            in_aux_line = True
            data.aux_section_seen = True
            continue

        intf_match = re.match(r"^interface\s+(\S+)$", line, flags=re.IGNORECASE)
        if intf_match:
            current_interface = Interface(name=intf_match.group(1))
            current_ospf_process = None
            in_bgp_section = False
            in_console_line = False
            in_vty_line = False
            in_aux_line = False
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
            acl_name, action, protocol, remainder = acl_match.groups()
            pieces = remainder.split()
            if len(pieces) >= 4:
                src = " ".join(pieces[:2])
                dst = " ".join(pieces[2:4])
            elif len(pieces) >= 2:
                src = pieces[0]
                dst = pieces[1]
            else:
                src = remainder
                dst = ""
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

        if in_console_line and re.match(
            r"^exec-timeout\s+\d+(\s+\d+)?$", line, flags=re.IGNORECASE
        ):
            data.console_exec_timeout_set = True
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

        if in_vty_line and re.match(
            r"^exec-timeout\s+\d+(\s+\d+)?$", line, flags=re.IGNORECASE
        ):
            data.vty_exec_timeout_set = True
            continue

        if in_aux_line and re.match(r"^no\s+exec$", line, flags=re.IGNORECASE):
            data.aux_no_exec_set = True
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

    return data
