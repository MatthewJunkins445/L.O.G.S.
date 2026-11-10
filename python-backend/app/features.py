def extract_features(packet_data, window_size):
    if not packet_data:
        return None

    total_packets = float(len(packet_data))
    total_bytes = 0.0
    tcp_count = 0
    udp_count = 0
    syn_count = 0.0
    connection_keys = set()
    destination_ports = set()
    proto_types = set()

    for p in packet_data:
        total_bytes += p.get("length", 0)
        proto = p.get("proto")
        if proto:
            proto_types.add(proto)
        if proto == "TCP":
            tcp_count += 1
            syn_count += p.get("syn", 0)
        elif proto == "UDP":
            udp_count += 1

        src   = p.get("src")
        dst   = p.get("dst")
        sport = p.get("sport")
        dport = p.get("dport")
        if src and dst and sport is not None and dport is not None and proto:
            connection_keys.add((src, dst, sport, dport, proto))
        if dport is not None:
            destination_ports.add(dport)

    mean_len   = total_bytes / total_packets
    tcp_ratio  = tcp_count / total_packets
    udp_ratio  = udp_count / total_packets
    bytes_per_sec   = total_bytes / window_size if window_size > 0 else 0.0
    packets_per_sec = total_packets / window_size if window_size > 0 else 0.0

    connection_count = float(len(connection_keys))
    unique_destination_ports = float(len(destination_ports))
    protocol_diversity = float(len(proto_types))

    avg_packets_per_connection = total_packets / connection_count if connection_count > 0 else 0.0
    avg_bytes_per_connection   = total_bytes   / connection_count if connection_count > 0 else 0.0
    syn_ratio = syn_count / total_packets if total_packets > 0 else 0.0
    avg_packets_per_port = total_packets / unique_destination_ports if unique_destination_ports > 0 else 0.0

    return [
        total_packets,
        total_bytes,
        mean_len,
        tcp_ratio,
        udp_ratio,
        bytes_per_sec,
        syn_count,
        packets_per_sec,
        connection_count,
        avg_packets_per_connection,
        avg_bytes_per_connection,
        protocol_diversity,
        unique_destination_ports,
        syn_ratio,
        avg_packets_per_port,
    ]
