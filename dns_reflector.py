# dns_reflector.py
from scapy.all import sniff, send, IP, UDP, DNS, DNSRR, DNSQR # <--- 'send' is now imported
from datetime import datetime

def dns_responder(packet):
    """
    This function is called for every packet sniffed.
    If it's a DNS query, it sends a large, fake DNS response back to the spoofed source.
    """
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0:
        
        query_name = packet[DNSQR].qname
        spoofed_src_ip = packet[IP].src
        transaction_id = packet[DNS].id
        
        response_payload = (
            DNS(
                id=transaction_id,
                qr=1,
                aa=1,
                qd=packet[DNS].qd,
                an=DNSRR(rrname=query_name, type='A', rdata='1.2.3.4', ttl=60) /
                   DNSRR(rrname=query_name, type='A', rdata='1.2.3.5', ttl=60) /
                   DNSRR(rrname=query_name, type='A', rdata='1.2.3.6', ttl=60) /
                   DNSRR(rrname=query_name, type='A', rdata='1.2.3.7', ttl=60) * 10
            )
        )
        
        response_packet = IP(dst=spoofed_src_ip, src=packet[IP].dst) / UDP(dport=packet[UDP].sport, sport=53) / response_payload
        
        # This line will now work correctly
        send(response_packet, verbose=0)
        
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"[{ts}] [DNS REFLECTOR] :: Reflected DNS query for '{query_name.decode()}' back to {spoofed_src_ip}. Response size: {len(response_packet)} bytes.")

if __name__ == "__main__":
    print("[+] Local DNS Reflector started. Listening for DNS queries on localhost...")
    sniff(filter="udp and port 53 and dst host 127.0.0.1", prn=dns_responder, iface="lo")
