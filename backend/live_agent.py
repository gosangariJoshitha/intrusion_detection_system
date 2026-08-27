import time
import requests
import json
from collections import defaultdict
import threading
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, DNSQR
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    exit(1)

# Default basic features to mock NSL-KDD
DEFAULT_FEATURES = {
    'duration': 0.0,
    'src_bytes': 0.0,
    'dst_bytes': 0.0,
    'land': 0.0,
    'wrong_fragment': 0.0,
    'urgent': 0.0,
    'hot': 0.0,
    'num_failed_logins': 0.0,
    'logged_in': 0.0,
    'num_compromised': 0.0,
    'root_shell': 0.0,
    'su_attempted': 0.0,
    'num_root': 0.0,
    'num_file_creations': 0.0,
    'num_shells': 0.0,
    'num_access_files': 0.0,
    'num_outbound_cmds': 0.0,
    'is_host_login': 0.0,
    'is_guest_login': 0.0,
    'count': 1.0,
    'srv_count': 1.0,
    'serror_rate': 0.0,
    'srv_serror_rate': 0.0,
    'rerror_rate': 0.0,
    'srv_rerror_rate': 0.0,
    'same_srv_rate': 1.0,
    'diff_srv_rate': 0.0,
    'srv_diff_host_rate': 0.0,
    'dst_host_count': 1.0,
    'dst_host_srv_count': 1.0,
    'dst_host_same_srv_rate': 1.0,
    'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 0.0,
    'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 0.0,
    'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 0.0,
    'dst_host_srv_rerror_rate': 0.0,
    'protocol_type': 'tcp',
    'service': 'http',
    'flag': 'SF'
}

BACKEND_URL = "http://localhost:8000/api/ingest"
FLUSH_INTERVAL = 2.0
flows = defaultdict(lambda: {'src': None, 'dst': None, 'proto': 'tcp', 'src_bytes': 0, 'dst_bytes': 0, 'count': 0, 'url': None})

def process_packet(pkt):
    if not IP in pkt:
        return
        
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Ignore loopback for this demo unless explicitly wanted
    if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
        return
        
    proto = 'other'
    sport = 0
    dport = 0
    url = None
    
    if TCP in pkt:
        proto = 'tcp'
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if Raw in pkt and (dport == 80 or sport == 80):
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith('GET') or payload.startswith('POST'):
                lines = payload.split('\r\n')
                req_line = lines[0].split(' ')
                if len(req_line) > 1:
                    path = req_line[1]
                    host = ""
                    for line in lines:
                        if line.startswith('Host:'):
                            host = line.split(' ')[1]
                            break
                    url = f"http://{host}{path}"
    elif UDP in pkt:
        proto = 'udp'
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if DNSQR in pkt:
            url = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            
    elif pkt[IP].proto == 1:
        proto = 'icmp'
        
    flow_key = tuple(sorted([src_ip, dst_ip])) + (proto, sport, dport)
    flow = flows[flow_key]
    
    flow['src'] = src_ip
    flow['dst'] = dst_ip
    flow['proto'] = proto
    flow['count'] += 1
    if url and not flow['url']:
        flow['url'] = url
        
    if src_ip == flow['src']:
        flow['src_bytes'] += len(pkt)
    else:
        flow['dst_bytes'] += len(pkt)

def flush_flows():
    while True:
        time.sleep(FLUSH_INTERVAL)
        current_flows = list(flows.values())
        flows.clear()
        
        for f in current_flows:
            if not f['src']: continue
            
            # Map scapy proto to NSL-KDD proto string
            p_type = f['proto']
            if p_type not in ['tcp', 'udp', 'icmp']: p_type = 'tcp'
            
            features = DEFAULT_FEATURES.copy()
            features['protocol_type'] = p_type
            features['src_bytes'] = float(f['src_bytes'])
            features['dst_bytes'] = float(f['dst_bytes'])
            features['count'] = float(f['count'])
            
            payload = {
                "source_ip": f['src'],
                "dest_ip": f['dst'],
                "protocol": p_type.upper(),
                "url": f['url'],
                "features": features
            }
            
            try:
                requests.post(BACKEND_URL, json=payload, timeout=1.0)
            except Exception as e:
                pass # Ignore connection refused

def mock_sniffer():
    print(">>> FALLBACK MODE: Generating realistic 'live' HTTP traffic because WinPcap/Npcap is missing. <<<")
    import random
    domains = ["http://github.com/api", "http://google.com/search", "http://amazon.com/cart", "http://malicious-site.com/login"]
    while True:
        url = random.choice(domains)
        payload = {
            "source_ip": "192.168.1." + str(random.randint(10, 50)),
            "dest_ip": str(random.randint(1,255)) + ".12.34.56",
            "protocol": "TCP",
            "url": url,
            "features": DEFAULT_FEATURES.copy()
        }
        try:
            requests.post(BACKEND_URL, json=payload, timeout=1.0)
        except:
            pass
        time.sleep(random.uniform(1.0, 3.0))

def start_sniffer():
    print("Starting Live Capture Agent...")
    print(f"Flushing to {BACKEND_URL} every {FLUSH_INTERVAL}s")
    flusher = threading.Thread(target=flush_flows, daemon=True)
    flusher.start()
    
    from scapy.all import conf
    try:
        sniff(prn=process_packet, store=0)
    except Exception as e:
        print(f"Native sniffing failed: {e}")
        print("Note: To capture real packets on Windows, you must install Npcap (https://npcap.com/)")
        mock_sniffer()

if __name__ == "__main__":
    start_sniffer()
