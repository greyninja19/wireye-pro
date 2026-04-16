#!/usr/bin/env python3
"""
WireEye Pro — Advanced PCAP Forensics & Analysis Platform
Kali Linux | Security Research Tool
"""

import os, json, re, socket, hashlib, math, ipaddress
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import threading

app = Flask(__name__, static_folder='static', static_url_path='')

# ── Try importing pyshark / scapy gracefully ──────────────────────────────────
try:
    import pyshark
    PYSHARK_OK = True
except ImportError:
    PYSHARK_OK = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Known malicious / suspicious ports ────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444: 'Metasploit default',
    1337: 'Elite/Leet hacker',
    31337: 'Back Orifice RAT',
    6667: 'IRC (C2 common)',
    6666: 'IRC alt',
    1080: 'SOCKS proxy',
    3128: 'Squid proxy',
    8080: 'HTTP proxy / alt web',
    9001: 'Tor relay',
    9050: 'Tor SOCKS',
    9051: 'Tor control',
    1194: 'OpenVPN',
    4899: 'Radmin remote admin',
    5900: 'VNC (unencrypted)',
    23: 'Telnet (cleartext)',
    21: 'FTP (cleartext)',
    69: 'TFTP',
    135: 'RPC / WMI exploit',
    139: 'NetBIOS (SMB)',
    445: 'SMB (EternalBlue target)',
    3389: 'RDP (brute-force target)',
    5985: 'WinRM HTTP',
    5986: 'WinRM HTTPS',
    11211: 'Memcached (amplification)',
    1900: 'UPnP (amplification)',
    161: 'SNMP (amplification)',
    53: 'DNS',
    2323: 'Telnet alt (Mirai IoT)',
    7547: 'TR-069 (router exploit)',
    8443: 'HTTPS alt',
    10000: 'Webmin',
    27017: 'MongoDB (no auth)',
    6379: 'Redis (no auth)',
    5432: 'PostgreSQL',
    3306: 'MySQL',
    2181: 'Zookeeper',
    9200: 'Elasticsearch (no auth)',
}

COMMON_PORTS = {
    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 25: 'SMTP', 587: 'SMTP/TLS',
    110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S', 53: 'DNS',
    123: 'NTP', 67: 'DHCP', 68: 'DHCP', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 500: 'IKE/IPSec', 4500: 'NAT-T',
}

ATTACK_SIGNATURES = {
    'port_scan':         'Port scanning / reconnaissance',
    'syn_flood':         'SYN flood (DoS)',
    'arp_spoof':         'ARP spoofing / MITM',
    'dns_exfil':         'DNS data exfiltration',
    'http_brute':        'HTTP brute force login',
    'ssh_brute':         'SSH brute force',
    'rdp_brute':         'RDP brute force',
    'smb_recon':         'SMB reconnaissance / lateral movement',
    'icmp_flood':        'ICMP flood / ping flood',
    'data_exfil':        'Suspected data exfiltration (large outbound)',
    'c2_beacon':         'C2 beaconing pattern (periodic traffic)',
    'dns_tunnel':        'DNS tunnelling detected',
    'cleartext_creds':   'Cleartext credentials in transit',
    'lateral_movement':  'Lateral movement (internal scanning)',
}

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except:
        return False

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def get_country_hint(ip):
    """Simple ASN hint based on IP range — no API needed."""
    if is_private(ip): return 'Private/Internal'
    parts = ip.split('.')
    if not parts or not parts[0].isdigit(): return 'Unknown'
    first = int(parts[0])
    if 1 <= first <= 9: return 'IANA Special'
    if first in range(192, 199): return 'Various'
    return 'Internet'

def entropy_score(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c/total)*math.log2(c/total) for c in counts.values() if c > 0)


# ── PCAP Analysis Engine ───────────────────────────────────────────────────────

def analyse_pcap(filepath: str) -> dict:
    if not SCAPY_OK:
        return {'error': 'Scapy not installed. Run: pip install scapy'}

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {'error': f'Failed to parse PCAP: {str(e)}'}

    # ── Raw counters ──────────────────────────────────────────────────────────
    total_packets   = len(packets)
    total_bytes     = sum(len(p) for p in packets)
    protocols       = Counter()
    src_ips         = Counter()
    dst_ips         = Counter()
    src_ports       = Counter()
    dst_ports       = Counter()
    ip_pairs        = Counter()       # (src, dst) → count
    conversations   = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'ports': set()})
    tcp_flags       = Counter()
    dns_queries     = []
    dns_responses   = []
    http_requests   = []
    arp_table       = {}              # ip → mac
    arp_replies     = []
    timestamps      = []
    payload_sizes   = []
    icmp_counts     = Counter()
    syn_counts      = Counter()       # src → SYN count
    large_transfers = []
    raw_payloads    = []              # (src, dst, port, snippet)

    for pkt in packets:
        try:
            if hasattr(pkt, 'time'):
                timestamps.append(float(pkt.time))

            # ── Layer 3 (IP) ──────────────────────────────────────────────────
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                size  = len(pkt)
                payload_sizes.append(size)

                src_ips[src] += 1
                dst_ips[dst] += 1
                ip_pairs[(src, dst)] += 1

                key = tuple(sorted([src, dst]))
                conversations[key]['packets'] += 1
                conversations[key]['bytes']   += size
                conversations[key]['src'] = src
                conversations[key]['dst'] = dst

                # Protocol
                if TCP in pkt:
                    protocols['TCP'] += 1
                    sp = pkt[TCP].sport
                    dp = pkt[TCP].dport
                    src_ports[sp] += 1
                    dst_ports[dp] += 1
                    conversations[key]['ports'].add(dp)

                    flags = pkt[TCP].flags
                    if flags & 0x02:  # SYN
                        tcp_flags['SYN'] += 1
                        syn_counts[src] += 1
                    if flags & 0x10:  tcp_flags['ACK']  += 1
                    if flags & 0x01:  tcp_flags['FIN']  += 1
                    if flags & 0x04:  tcp_flags['RST']  += 1
                    if flags & 0x08:  tcp_flags['PSH']  += 1

                    # HTTP (raw payload sniff)
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        snippet = payload[:512]
                        if snippet.startswith(b'GET ') or snippet.startswith(b'POST ') or \
                           snippet.startswith(b'PUT ') or snippet.startswith(b'DELETE ') or \
                           snippet.startswith(b'HEAD '):
                            try:
                                lines = snippet.decode('utf-8', errors='ignore').split('\r\n')
                                method_line = lines[0]
                                headers = {}
                                for line in lines[1:]:
                                    if ': ' in line:
                                        k, v = line.split(': ', 1)
                                        headers[k.lower()] = v
                                http_requests.append({
                                    'src': src, 'dst': dst,
                                    'method': method_line.split()[0] if method_line else '?',
                                    'path': method_line.split()[1] if len(method_line.split()) > 1 else '/',
                                    'host': headers.get('host', dst),
                                    'user_agent': headers.get('user-agent', ''),
                                    'size': size,
                                })
                            except:
                                pass

                        # Check for cleartext creds
                        pl_str = payload.decode('utf-8', errors='ignore').lower()
                        if any(kw in pl_str for kw in ['password=', 'passwd=', 'pass=', 'pwd=', 'secret=']):
                            raw_payloads.append({
                                'type': 'cleartext_credential',
                                'src': src, 'dst': dst,
                                'port': dp,
                                'snippet': pl_str[:200],
                            })

                elif UDP in pkt:
                    protocols['UDP'] += 1
                    sp = pkt[UDP].sport
                    dp = pkt[UDP].dport
                    src_ports[sp] += 1
                    dst_ports[dp] += 1
                    conversations[key]['ports'].add(dp)

                    # DNS
                    if DNS in pkt:
                        protocols['DNS'] += 1
                        dns_pkt = pkt[DNS]
                        if dns_pkt.qr == 0 and DNSQR in pkt:  # Query
                            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            dns_queries.append({'src': src, 'dst': dst, 'query': qname, 'type': pkt[DNSQR].qtype})
                        elif dns_pkt.qr == 1 and DNSRR in pkt:  # Response
                            rdata = str(pkt[DNSRR].rdata) if hasattr(pkt[DNSRR], 'rdata') else '?'
                            qname = pkt[DNSRR].rrname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(pkt[DNSRR], 'rrname') else '?'
                            dns_responses.append({'src': src, 'dst': dst, 'name': qname, 'data': rdata})

                elif ICMP in pkt:
                    protocols['ICMP'] += 1
                    icmp_counts[src] += 1

                # Large transfer detection
                if size > 10000:
                    large_transfers.append({'src': src, 'dst': dst, 'size': size})

            # ── ARP ──────────────────────────────────────────────────────────
            if ARP in pkt:
                protocols['ARP'] += 1
                if pkt[ARP].op == 2:  # ARP reply
                    ip  = pkt[ARP].psrc
                    mac = pkt[ARP].hwsrc
                    if ip in arp_table and arp_table[ip] != mac:
                        arp_replies.append({
                            'ip': ip,
                            'old_mac': arp_table[ip],
                            'new_mac': mac,
                        })
                    arp_table[ip] = mac

        except Exception:
            continue

    # ── Time range ────────────────────────────────────────────────────────────
    if timestamps:
        ts_start = datetime.utcfromtimestamp(min(timestamps)).strftime('%Y-%m-%d %H:%M:%S UTC')
        ts_end   = datetime.utcfromtimestamp(max(timestamps)).strftime('%Y-%m-%d %H:%M:%S UTC')
        duration = round(max(timestamps) - min(timestamps), 2)
    else:
        ts_start = ts_end = 'Unknown'
        duration = 0

    # ── Top talkers ──────────────────────────────────────────────────────────
    top_src = [{'ip': ip, 'count': c, 'private': is_private(ip)} for ip, c in src_ips.most_common(15)]
    top_dst = [{'ip': ip, 'count': c, 'private': is_private(ip)} for ip, c in dst_ips.most_common(15)]
    top_dst_ports = [{'port': p, 'count': c, 'service': COMMON_PORTS.get(p, SUSPICIOUS_PORTS.get(p, 'Unknown'))} for p, c in dst_ports.most_common(20)]

    # ── Conversation list ─────────────────────────────────────────────────────
    conv_list = []
    for (a, b), info in sorted(conversations.items(), key=lambda x: x[1]['bytes'], reverse=True)[:30]:
        conv_list.append({
            'a': info.get('src', a), 'b': info.get('dst', b),
            'packets': info['packets'],
            'bytes': info['bytes'],
            'ports': sorted(list(info['ports']))[:10],
        })

    # ── Threat detection ─────────────────────────────────────────────────────
    threats = []
    threat_details = []

    # 1. Port scan: one src → many distinct dst ports
    dst_ports_per_src = defaultdict(set)
    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt:
                dst_ports_per_src[pkt[IP].src].add(pkt[TCP].dport)
        except:
            pass
    for src, ports in dst_ports_per_src.items():
        if len(ports) > 30:
            threats.append('port_scan')
            threat_details.append({
                'type': 'port_scan',
                'label': ATTACK_SIGNATURES['port_scan'],
                'severity': 'HIGH',
                'src': src,
                'detail': f'{src} scanned {len(ports)} ports',
            })

    # 2. SYN flood: very high SYN rate from one source
    for src, count in syn_counts.items():
        if count > 500:
            threats.append('syn_flood')
            threat_details.append({
                'type': 'syn_flood',
                'label': ATTACK_SIGNATURES['syn_flood'],
                'severity': 'CRITICAL',
                'src': src,
                'detail': f'{src} sent {count} SYN packets',
            })

    # 3. ARP spoofing
    if arp_replies:
        threats.append('arp_spoof')
        for r in arp_replies:
            threat_details.append({
                'type': 'arp_spoof',
                'label': ATTACK_SIGNATURES['arp_spoof'],
                'severity': 'HIGH',
                'src': r['ip'],
                'detail': f'IP {r["ip"]} changed MAC: {r["old_mac"]} → {r["new_mac"]}',
            })

    # 4. DNS tunnelling: very long query names (>50 chars encoded)
    dns_tunnel_suspects = [q for q in dns_queries if len(q['query']) > 50]
    if dns_tunnel_suspects:
        threats.append('dns_tunnel')
        for q in dns_tunnel_suspects[:3]:
            threat_details.append({
                'type': 'dns_tunnel',
                'label': ATTACK_SIGNATURES['dns_tunnel'],
                'severity': 'HIGH',
                'src': q['src'],
                'detail': f'Long DNS query ({len(q["query"])} chars): {q["query"][:80]}',
            })

    # 5. SSH brute force: many TCP connections to port 22
    ssh_conns = Counter()
    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt and pkt[TCP].dport == 22 and pkt[TCP].flags & 0x02:
                ssh_conns[pkt[IP].src] += 1
        except:
            pass
    for src, count in ssh_conns.items():
        if count > 20:
            threats.append('ssh_brute')
            threat_details.append({
                'type': 'ssh_brute',
                'label': ATTACK_SIGNATURES['ssh_brute'],
                'severity': 'HIGH',
                'src': src,
                'detail': f'{src} made {count} SYN attempts to port 22',
            })

    # 6. RDP brute force
    rdp_conns = Counter()
    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt and pkt[TCP].dport == 3389 and pkt[TCP].flags & 0x02:
                rdp_conns[pkt[IP].src] += 1
        except:
            pass
    for src, count in rdp_conns.items():
        if count > 10:
            threats.append('rdp_brute')
            threat_details.append({
                'type': 'rdp_brute',
                'label': ATTACK_SIGNATURES['rdp_brute'],
                'severity': 'HIGH',
                'src': src,
                'detail': f'{src} made {count} SYN attempts to RDP port 3389',
            })

    # 7. ICMP flood
    for src, count in icmp_counts.items():
        if count > 100:
            threats.append('icmp_flood')
            threat_details.append({
                'type': 'icmp_flood',
                'label': ATTACK_SIGNATURES['icmp_flood'],
                'severity': 'MEDIUM',
                'src': src,
                'detail': f'{src} sent {count} ICMP packets',
            })

    # 8. Cleartext credentials
    if raw_payloads:
        threats.append('cleartext_creds')
        for p in raw_payloads[:5]:
            threat_details.append({
                'type': 'cleartext_creds',
                'label': ATTACK_SIGNATURES['cleartext_creds'],
                'severity': 'CRITICAL',
                'src': p['src'],
                'detail': f'Port {p["port"]}: {p["snippet"][:100]}',
            })

    # 9. SMB recon (445)
    smb_count = sum(1 for pkt in packets if IP in pkt and TCP in pkt and pkt[TCP].dport == 445)
    if smb_count > 50:
        threats.append('smb_recon')
        threat_details.append({
            'type': 'smb_recon',
            'label': ATTACK_SIGNATURES['smb_recon'],
            'severity': 'HIGH',
            'src': 'Multiple',
            'detail': f'{smb_count} packets to SMB port 445',
        })

    # 10. Suspicious port usage
    suspicious_port_hits = []
    for port, label in SUSPICIOUS_PORTS.items():
        if port in dst_ports and port not in (53, 8080):  # skip common false positives
            count = dst_ports[port]
            suspicious_port_hits.append({'port': port, 'label': label, 'count': count})

    # 11. Lateral movement: internal → internal scanning
    internal_scan = defaultdict(set)
    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt:
                s, d = pkt[IP].src, pkt[IP].dst
                if is_private(s) and is_private(d) and s != d:
                    internal_scan[s].add(d)
        except:
            pass
    for src, dsts in internal_scan.items():
        if len(dsts) > 5:
            threats.append('lateral_movement')
            threat_details.append({
                'type': 'lateral_movement',
                'label': ATTACK_SIGNATURES['lateral_movement'],
                'severity': 'HIGH',
                'src': src,
                'detail': f'{src} connected to {len(dsts)} internal hosts',
            })
            break

    # ── Endpoint summary ──────────────────────────────────────────────────────
    all_ips = set(src_ips.keys()) | set(dst_ips.keys())
    endpoints = []
    for ip in sorted(all_ips)[:50]:
        endpoints.append({
            'ip': ip,
            'sent': src_ips.get(ip, 0),
            'received': dst_ips.get(ip, 0),
            'private': is_private(ip),
            'role': 'Internal' if is_private(ip) else 'External',
        })

    # ── Protocol breakdown ────────────────────────────────────────────────────
    proto_total = sum(protocols.values()) or 1
    protocol_breakdown = [
        {'name': k, 'count': v, 'pct': round(v / proto_total * 100, 1)}
        for k, v in protocols.most_common()
    ]

    # ── DNS summary ───────────────────────────────────────────────────────────
    queried_domains = Counter(q['query'] for q in dns_queries)
    top_domains = [{'domain': d, 'count': c} for d, c in queried_domains.most_common(20)]

    # ── Traffic timeline (bucket by second) ───────────────────────────────────
    if timestamps:
        base = int(min(timestamps))
        buckets = Counter(int(t) - base for t in timestamps)
        timeline = [{'t': k, 'count': v} for k, v in sorted(buckets.items())]
    else:
        timeline = []

    # ── Risk score ────────────────────────────────────────────────────────────
    risk_score = 0
    if 'port_scan'       in threats: risk_score += 30
    if 'syn_flood'       in threats: risk_score += 40
    if 'arp_spoof'       in threats: risk_score += 35
    if 'dns_tunnel'      in threats: risk_score += 30
    if 'ssh_brute'       in threats: risk_score += 25
    if 'rdp_brute'       in threats: risk_score += 25
    if 'icmp_flood'      in threats: risk_score += 15
    if 'cleartext_creds' in threats: risk_score += 40
    if 'smb_recon'       in threats: risk_score += 25
    if 'lateral_movement'in threats: risk_score += 30
    risk_score = min(risk_score, 100)

    if risk_score == 0:   risk_label = '✅ CLEAN'
    elif risk_score < 30: risk_label = '⚠️ LOW RISK'
    elif risk_score < 60: risk_label = '🚨 MEDIUM RISK'
    elif risk_score < 80: risk_label = '🔥 HIGH RISK'
    else:                 risk_label = '💀 CRITICAL'

    return {
        'meta': {
            'filename': os.path.basename(filepath),
            'file_size': os.path.getsize(filepath),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'capture_start': ts_start,
            'capture_end': ts_end,
            'duration_sec': duration,
            'analysed_at': datetime.utcnow().isoformat() + 'Z',
        },
        'risk': {
            'score': risk_score,
            'label': risk_label,
            'threat_count': len(set(threats)),
        },
        'protocols': protocol_breakdown,
        'top_src_ips': top_src,
        'top_dst_ips': top_dst,
        'top_dst_ports': top_dst_ports,
        'conversations': conv_list,
        'endpoints': endpoints,
        'threats': threat_details,
        'suspicious_ports': suspicious_port_hits,
        'dns': {
            'queries': dns_queries[:100],
            'responses': dns_responses[:50],
            'top_domains': top_domains,
        },
        'http': {
            'requests': http_requests[:100],
        },
        'arp': {
            'table': [{'ip': ip, 'mac': mac} for ip, mac in list(arp_table.items())[:50]],
            'spoof_events': arp_replies,
        },
        'timeline': timeline[:300],
        'tcp_flags': dict(tcp_flags),
        'large_transfers': large_transfers[:20],
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'})
    f = request.files['file']
    if not f.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
        return jsonify({'error': 'File must be .pcap, .pcapng, or .cap'})

    os.makedirs('/tmp/wireeye', exist_ok=True)
    path = f'/tmp/wireeye/{hashlib.md5(f.filename.encode()).hexdigest()}_{f.filename}'
    f.save(path)

    result = analyse_pcap(path)
    return jsonify(result)


@app.route('/api/status')
def status():
    return jsonify({'scapy': SCAPY_OK, 'pyshark': PYSHARK_OK})


if __name__ == '__main__':
    from colorama import Fore, Style, init as ci
    ci(autoreset=True)
    print(f"\n{Fore.CYAN}{'═'*55}")
    print("  WireEye Pro  |  PCAP Forensics Platform")
    print(f"  http://127.0.0.1:5000")
    print(f"{'═'*55}{Style.RESET_ALL}\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
