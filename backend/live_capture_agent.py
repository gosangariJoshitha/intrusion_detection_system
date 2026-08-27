"""
Live network capture agent.

Run this LOCALLY (on your own laptop, with admin/root privileges) to sniff
real packets on your network interface, turn them into simplified
NSL-KDD-style flow features, and POST them to your deployed backend's
/ingest endpoint for real-time scoring.

IMPORTANT — read this before you present the project:
Full NSL-KDD-quality feature extraction (all 41 features, including things
like same_srv_rate computed over a proper 2-second host-connection window)
is normally done by dedicated tools like CICFlowMeter or Zeek. This script
is a best-effort simplified approximation — duration, byte counts, and
basic connection counts per (source, destination) pair over a short
window — built for demo purposes so live traffic can hit the same model.
It is NOT production-grade traffic analysis. Say so if you're asked in a
viva/interview; it's a legitimate and common simplification for a student
project, but don't present it as full flow-level extraction.

Requirements:
    pip install scapy requests

Usage:
    sudo python3 live_capture_agent.py --backend https://your-backend-url --iface eth0
    (On Windows, run as Administrator and drop --iface, or use the Npcap
    interface name shown by `scapy.arch.windows.get_windows_if_list()`.)
"""
import argparse
import time
import threading
import requests
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    raise SystemExit("Install scapy first:  pip install scapy")

COMMON_PORTS = {
    80: "http", 443: "http", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "domain_u", 110: "pop_3", 143: "imap4", 3306: "sql_net",
}

WINDOW_SECONDS = 2.0

_lock = threading.Lock()
_flows = defaultdict(lambda: {
    "start": None, "src_bytes": 0, "dst_bytes": 0, "packets": 0,
    "proto": "tcp", "service": "other",
})


def _flow_key(src, dst, proto):
    return (src, dst, proto)


def _service_for_port(port):
    return COMMON_PORTS.get(port, "other")


def handle_packet(pkt):
    if IP not in pkt:
        return
    src, dst = pkt[IP].src, pkt[IP].dst
    length = len(pkt)

    if TCP in pkt:
        proto = "tcp"
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "udp"
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "icmp"
        dport = 0
    else:
        return

    key = _flow_key(src, dst, proto)
    with _lock:
        f = _flows[key]
        if f["start"] is None:
            f["start"] = time.time()
        f["src_bytes"] += length
        f["packets"] += 1
        f["proto"] = proto
        f["service"] = _service_for_port(dport)


def flush_loop(backend_url):
    while True:
        time.sleep(WINDOW_SECONDS)
        with _lock:
            items = list(_flows.items())
            _flows.clear()

        for (src, dst, proto), f in items:
            duration = max(0.0, time.time() - f["start"]) if f["start"] else 0.0
            record = {
                "_source_ip": src,
                "_dest_ip": dst,
                "duration": round(duration, 2),
                "protocol_type": proto,
                "service": f["service"],
                "flag": "SF",
                "src_bytes": f["src_bytes"],
                "dst_bytes": 0,
                "count": f["packets"],
                "srv_count": f["packets"],
                "same_srv_rate": 1.0,
                "logged_in": 1 if f["service"] in ("http", "ssh", "ftp") else 0,
            }
            try:
                requests.post(f"{backend_url}/ingest", json=record, timeout=3)
            except requests.RequestException as e:
                print(f"[warn] failed to reach backend: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", required=True, help="Deployed backend base URL, e.g. https://your-app.onrender.com")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (omit to use default)")
    args = parser.parse_args()

    print(f"Starting capture -> {args.backend}/ingest  (window={WINDOW_SECONDS}s)")
    print("Remember: set the backend to 'live' mode from the dashboard, or via")
    print(f"  curl -X POST {args.backend}/mode -H 'Content-Type: application/json' -d '{{\"mode\":\"live\"}}'")

    t = threading.Thread(target=flush_loop, args=(args.backend,), daemon=True)
    t.start()

    sniff(iface=args.iface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
