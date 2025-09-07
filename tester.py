# tester.py
import joblib
from scapy.all import rdpcap, IP, UDP, DNS
import pandas as pd
import warnings
import os

# Suppress a specific Scapy warning that is not relevant here
warnings.filterwarnings("ignore", category=UserWarning, module="scapy.layers.inet")

def extract_features_from_mixed_traffic(pcap_file, victim_ip='192.168.1.100'):
    """
    Reads the mixed pcap file containing benign, known (CoAP), and unknown (DNS) attacks.
    It extracts features and assigns a "ground truth" label to each packet for evaluation.
    """
    if not os.path.exists(pcap_file):
        print(f"[!] Error: Pcap file not found at '{pcap_file}'. Please generate it first.")
        return pd.DataFrame()

    packets = rdpcap(pcap_file)
    features = []
    
    for packet in packets:
        # We only care about traffic that is being sent TO the victim.
        if IP not in packet or UDP not in packet or packet[IP].dst != victim_ip:
            continue
            
        pkt_len = len(packet)
        
        # This is our ground truth for the experiment. Is this packet a DNS attack?
        true_label = "Known Attack (CoAP)"
        if DNS in packet:
            true_label = "Zero-Day Attack (DNS)"
            
        features.append([pkt_len, true_label])
        
    return pd.DataFrame(features, columns=['packet_length', 'true_label'])

# --- Main Execution Block ---
if __name__ == "__main__":
    MODEL_FILE = 'supervised_model.joblib'
    PCAP_FILE = 'coap_new_dns.pcap' # The file with all three traffic types

    if not os.path.exists(MODEL_FILE):
        print(f"[!] Error: Model file '{MODEL_FILE}' not found. Please run trainer.py first.")
    else:
        print(f"[+] Loading the pre-trained CoAP-only supervised model from '{MODEL_FILE}'...")
        model = joblib.load(MODEL_FILE)

        print(f"[+] Analyzing mixed traffic from '{PCAP_FILE}' to test for zero-day vulnerability...")
        df = extract_features_from_mixed_traffic(PCAP_FILE)

        if not df.empty:
            # Predict using the loaded model
            X_mixed = df[['packet_length']]
            predictions = model.predict(X_mixed)
            df['predicted_label'] = ['Benign' if x == 0 else 'Known Attack (CoAP)' for x in predictions]

            # --- Results ---
            print("\n--- Zero-Day Detection Test Results ---")
            dns_attacks = df[df['true_label'] == 'Zero-Day Attack (DNS)']
            missed_dns_attacks = dns_attacks[dns_attacks['predicted_label'] == 'Benign']

            total_dns_attacks = len(dns_attacks)
            total_missed = len(missed_dns_attacks)

            print(f"Total DNS Attack Packets Found: {total_dns_attacks}")
            print(f"DNS Attack Packets MISSED (classified as Benign): {total_missed}")

            detection_rate = 0
            if total_dns_attacks > 0:
                detection_rate = ((total_dns_attacks - total_missed) / total_dns_attacks) * 100

            print(f"\nZero-Day (DNS) Attack Detection Rate: {detection_rate:.2f}%")
            print("-----------------------------------------")

            if detection_rate < 10:
                print("\n[SUCCESS] The experiment has successfully demonstrated the research gap.")
                print("[INFO] The supervised-only model is blind to the novel DNS attack, as expected.")
