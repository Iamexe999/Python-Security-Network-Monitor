import argparse
import logging
from collections import defaultdict
from datetime import datetime
from scapy.all import *
from scapy.layers import http

class NetworkMonitor:
    def __init__(self, interface=None, show_payload=False):
        self.interface = interface or conf.iface  # Use default interface if none provided
        self.show_payload = show_payload
        self.arp_table = defaultdict(str)
        self.port_scan_threshold = 5  # Alert after 5 rapid connections
        self.connection_counts = defaultdict(int)
        self.alerts = []

    def start_capture(self):
        try:
            print(f"Starting capture on interface {self.interface}...")
            sniff(iface=self.interface, prn=self.process_packet, store=False)
        except PermissionError:
            print("ERROR: You need root/administrator privileges to capture packets.")
        except Exception as e:
            print(f"ERROR: {e}")

    def process_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            # Basic packet information
            print(f"[*] {src_ip} -> {dst_ip} | Proto: {proto}")

            # Detect HTTP traffic
            if packet.haslayer(http.HTTPRequest):
                self.detect_http(packet)

            # Detect ARP spoofing
            if packet.haslayer(ARP):
                self.detect_arp_spoofing(packet)

            # Detect port scanning
            if packet.haslayer(TCP) and packet[TCP].flags == 'S':
                self.detect_port_scan(src_ip)

            # Optional payload display
            if self.show_payload and packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"[Payload] {payload[:50]}...")

    def detect_arp_spoofing(self, packet):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                alert = f"ARP Spoofing detected! {ip} changed from {self.arp_table[ip]} to {mac}"
                self.trigger_alert(alert)
        else:
            self.arp_table[ip] = mac

    def detect_port_scan(self, src_ip):
        self.connection_counts[src_ip] += 1
        if self.connection_counts[src_ip] > self.port_scan_threshold:
            alert = f"Port scan detected from {src_ip}"
            self.trigger_alert(alert)
            self.connection_counts[src_ip] = 0  # Reset counter

    def detect_http(self, packet):
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        print(f"[HTTP Request] {host}{path}")

    def trigger_alert(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[ALERT] {timestamp} - {message}"
        self.alerts.append(alert_msg)
        print(alert_msg)
        self.log_alert(alert_msg)

    def log_alert(self, message):
        logging.basicConfig(filename='network_alerts.log', level=logging.INFO)
        logging.info(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyNetGuard - Network Security Monitor")
    parser.add_argument("-i", "--interface", help="Network interface (default: auto-detect)")
    parser.add_argument("-p", "--show-payload", action="store_true", help="Show packet payloads")
    args = parser.parse_args()

    monitor = NetworkMonitor(args.interface, args.show_payload)
    monitor.start_capture()