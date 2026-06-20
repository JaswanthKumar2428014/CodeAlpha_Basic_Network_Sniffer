#!/usr/bin/env python3
"""
Network Packet Sniffer & Analyzer
==================================
An educational tool to capture live network traffic and inspect how
data flows through the protocol stack (Ethernet -> IP -> TCP/UDP/ICMP -> payload).

Requires root/administrator privileges to capture packets:
    sudo python3 packet_sniffer.py

Usage examples:
    sudo python3 packet_sniffer.py                  # sniff all traffic, no limit
    sudo python3 packet_sniffer.py -i eth0 -c 50     # 50 packets on interface eth0
    sudo python3 packet_sniffer.py -f "tcp port 80"  # BPF filter for HTTP traffic
    sudo python3 packet_sniffer.py --save capture.pcap
"""

import argparse
import datetime
import sys

try:
    from scapy.all import (
        sniff, wrpcap, conf,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
    )
except ImportError:
    sys.exit("scapy is required. Install it with: pip install scapy")


# Map well-known ports to protocol names for readability
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}

captured_packets = []
packet_count = 0


def service_name(port):
    return COMMON_PORTS.get(port, str(port))


def describe_l4(pkt):
    """Return (protocol_name, src_port, dst_port, extra_info) for transport layer."""
    if pkt.haslayer(TCP):
        l = pkt[TCP]
        flags = l.sprintf("%TCP.flags%")
        return "TCP", l.sport, l.dport, f"flags={flags} seq={l.seq} ack={l.ack}"
    if pkt.haslayer(UDP):
        l = pkt[UDP]
        return "UDP", l.sport, l.dport, f"len={l.len}"
    if pkt.haslayer(ICMP):
        l = pkt[ICMP]
        return "ICMP", None, None, f"type={l.type} code={l.code}"
    return None, None, None, None


def get_payload_preview(pkt, max_bytes=64):
    """Extract raw application-layer bytes and show a safe printable preview."""
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        preview = data[:max_bytes]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
        hexed = preview.hex()
        return len(data), text, hexed
    return 0, "", ""


def process_packet(pkt):
    global packet_count
    packet_count += 1
    captured_packets.append(pkt)

    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    lines = [f"\n[{packet_count}] {ts}  |  {len(pkt)} bytes"]

    # --- Layer 2: Ethernet ---
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        lines.append(f"  Ethernet : {eth.src} -> {eth.dst}  (type=0x{eth.type:04x})")

    # --- Layer 3: IP / IPv6 / ARP ---
    src_ip = dst_ip = proto_name = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst
        proto_name = ip.sprintf("%IP.proto%")
        lines.append(
            f"  IPv4     : {src_ip} -> {dst_ip}  (proto={proto_name}, ttl={ip.ttl}, len={ip.len})"
        )
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip, dst_ip = ip6.src, ip6.dst
        lines.append(f"  IPv6     : {src_ip} -> {dst_ip}  (nh={ip6.nh}, hlim={ip6.hlim})")
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "request" if arp.op == 1 else "reply" if arp.op == 2 else arp.op
        lines.append(f"  ARP      : {arp.psrc} -> {arp.pdst}  ({op})")

    # --- Layer 4: TCP / UDP / ICMP ---
    l4_proto, sport, dport, extra = describe_l4(pkt)
    if l4_proto:
        if sport is not None:
            lines.append(
                f"  {l4_proto:<8} : {src_ip}:{sport} ({service_name(sport)}) -> "
                f"{dst_ip}:{dport} ({service_name(dport)})  [{extra}]"
            )
        else:
            lines.append(f"  {l4_proto:<8} : {src_ip} -> {dst_ip}  [{extra}]")

    # --- Application layer payload ---
    plen, text_preview, hex_preview = get_payload_preview(pkt)
    if plen:
        lines.append(f"  Payload  : {plen} bytes")
        lines.append(f"    ascii: {text_preview}")
        lines.append(f"    hex  : {hex_preview}")

    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Educational network packet sniffer")
    parser.add_argument("-i", "--iface", default=None, help="Network interface (default: scapy auto-pick)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80' or 'udp port 53'")
    parser.add_argument("--save", default=None, help="Save captured packets to a .pcap file")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Stop sniffing after N seconds")
    args = parser.parse_args()

    print("=" * 70)
    print(" Network Packet Sniffer & Analyzer")
    print("=" * 70)
    print(f" Interface : {args.iface or '(auto)'}")
    print(f" Filter    : {args.filter or '(none, capturing all traffic)'}")
    print(f" Count     : {'infinite (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)

    if conf.iface is None and args.iface is None:
        print("Tip: use -i to specify a network interface if auto-detect picks the wrong one.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count,
            timeout=args.timeout,
            store=False,
        )
    except PermissionError:
        sys.exit(
            "Permission denied. Packet capture requires elevated privileges.\n"
            "Try: sudo python3 packet_sniffer.py"
        )
    except KeyboardInterrupt:
        pass

    print(f"\n\nCapture stopped. Total packets captured: {packet_count}")

    if args.save and captured_packets:
        wrpcap(args.save, captured_packets)
        print(f"Saved {len(captured_packets)} packets to {args.save}")
        print(f"You can open this file later with Wireshark or scapy's rdpcap().")


if __name__ == "__main__":
    main()
