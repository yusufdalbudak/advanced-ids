from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS # type: ignore
import DetectionEngine
import Logger
import threading
from datetime import datetime

stop_sniffing = threading.Event()
log_callback = None  # Define a global variable for the log callback

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = bytes(packet[IP].payload)
        
        # Log packet information
        log_packet_info(src_ip, dst_ip, proto)

        # Saldırı tespiti
        if DetectionEngine.detect_syn_flood(packet):
            threat_info = f"SYN Flood detected"
        elif DetectionEngine.detect_icmp_flood(packet):
            threat_info = f"ICMP Flood detected"
        elif DetectionEngine.detect_udp_flood(packet):
            threat_info = f"UDP Flood detected"
        elif DetectionEngine.detect_dns_amplification(packet):
            threat_info = f"DNS Amplification detected"
        elif DetectionEngine.detect_http_flood(packet):
            threat_info = f"HTTP Flood detected"
        elif DetectionEngine.detect_anomaly(packet):
            threat_info = f"Anomaly detected"
        elif packet.haslayer(ARP):
            threat_info = f"ARP Packet detected"
        elif packet.haslayer(DNS):
            threat_info = f"DNS Packet detected"
        else:
            return  # No threat detected, exit early

        Logger.log_threat_to_db(threat_info)
        Logger.log_threat_to_csv(threat_info, src_ip, dst_ip, proto)

def log_packet_info(src_ip, dst_ip, proto):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}"
    if log_callback:
        log_callback(message)  # Use the callback to log the message in the UI

def start_packet_capture(interface='Ethernet', log_func=None):
    global log_callback
    log_callback = log_func  # Set the log callback
    print("Starting packet capture...")
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffing.is_set())
    # Consider using PyShark for more advanced packet analysis

def stop_packet_capture():
    stop_sniffing.set() 

def isolate_suspicious_device(ip):
    # Placeholder for logic to isolate a device
    print(f"Isolating device with IP: {ip}")
    # Implement network isolation logic here 

def configure_firewall_rules(ip):
    # Placeholder for firewall rule configuration
    print(f"Configuring firewall to block traffic from IP: {ip}")
    # Implement firewall rule logic here 

def update_and_scan_device(ip):
    # Placeholder for update and scan logic
    print(f"Updating and scanning device with IP: {ip}")
    # Implement update and vulnerability scan logic here 