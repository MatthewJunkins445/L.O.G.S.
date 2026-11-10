import logging
import platform
import socket
import time
from typing import Optional
from scapy.all import sniff, get_if_list, IP, TCP, UDP

logger = logging.getLogger("logs.capture")


def _score_interface(name: str) -> int:
    """Score an interface description. Higher = more preferred."""
    n = name.lower()
    if any(x in n for x in ('loopback', 'npcap loopback')):
        return -100
    if any(x in n for x in ('vpn', 'tunnel', 'tap', 'tun', 'virtual', 'vmware',
                             'virtualbox', 'hyper-v', 'wi-fi direct', 'bluetooth')):
        return -20
    if any(x in n for x in ('ethernet', 'local area', 'realtek', 'intel',
                             'broadcom', 'atheros', 'killer')):
        return 20
    if any(x in n for x in ('wi-fi', 'wireless', 'wlan', '802.11', 'airport')):
        return 15
    return 0


def get_interface() -> str:
    """
    Return the best network interface for packet capture.

    Windows: scores each interface by its friendly description via scapy's
    conf.ifaces, preferring Ethernet/Wi-Fi and skipping loopback/VPN adapters.
    Linux/macOS: tries common names in preference order, skips loopback.
    """
    interfaces = get_if_list()
    if not interfaces:
        raise RuntimeError(
            "No network interfaces found. "
            "Ensure Npcap (Windows) or libpcap (Linux) is installed."
        )

    if platform.system() == "Windows":
        try:
            from scapy.config import conf
            scored = []
            for pcap_name in interfaces:
                iface = conf.ifaces.get(pcap_name)
                desc = (getattr(iface, 'description', '') or pcap_name)
                score = _score_interface(desc)
                scored.append((pcap_name, score, desc))
                logger.debug(f"  iface {desc!r} → score {score}")

            scored.sort(key=lambda x: x[1], reverse=True)
            best_name, best_score, best_desc = scored[0]
            logger.info(f"Selected interface: {best_desc!r} (score={best_score})")
            return best_name
        except Exception as exc:
            logger.warning(f"Windows interface auto-detect failed ({exc}), using first interface")
            return interfaces[0]

    # Linux / macOS — try common names first, then skip loopback
    preferred = ['eth0', 'en0', 'ens33', 'ens3', 'ens4',
                 'wlan0', 'wlo1', 'wlp2s0', 'wlp3s0']
    for name in preferred:
        if name in interfaces:
            logger.info(f"Selected interface: {name}")
            return name
    for name in interfaces:
        if name != 'lo' and not name.startswith('lo'):
            logger.info(f"Selected interface: {name}")
            return name
    logger.warning(f"Only loopback available, using: {interfaces[0]}")
    return interfaces[0]


def get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def capture_window(interface: str, window_size: int) -> list:
    local_buffer = []

    def _process_packet(packet):
        if not packet.haslayer(IP):
            return
        proto = None
        sport = None
        dport = None
        syn = 0
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
            syn = 1 if (packet[TCP].flags & 0x02) != 0 else 0
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        else:
            proto = "OTHER"
        local_buffer.append({
            "length": int(len(packet)),
            "src":    packet[IP].src,
            "dst":    packet[IP].dst,
            "proto":  proto,
            "sport":  sport,
            "dport":  dport,
            "syn":    syn,
            "time":   float(time.time()),
        })

    sniff(iface=interface, prn=_process_packet, timeout=window_size, store=False)
    return local_buffer
