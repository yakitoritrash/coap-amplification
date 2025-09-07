# trainer.py
from scapy.all import rdpcap, IP, UDP
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import warnings
import os
import joblib

warnings.filterwarnings("ignore", category=UserWarning, module="scapy.layers.inet")

def extract_features(pcap_file, benign_ip='127.0.0.1', victim_ip='192.168.1.100', server_ip='127.0.0.1'):
    packets = rdpcap(pcap_file)
    features = []
    
    print(f"Processing {len(packets)} packets from {pcap_file}...")
    
    for packet in packets:
        if IP not in packet or UDP not in packet:
            continue
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)
        
        # --- CORRECTED LABELING LOGIC ---
        # A packet is only BENIGN if it's a request from the benign client.
        if src_ip == benign_ip and dst_ip == server_ip:
            label = 0 # Benign
            features.append([pkt_len, label])
            
        # A packet is only MALICIOUS if it's a response from the server
        # to the spoofed VICTIM'S IP.
        elif src_ip == server_ip and dst_ip == victim_ip:
            label = 1 # Malicious (Attack)
            features.append([pkt_len, label])
        
        # We now correctly IGNORE all other packets, including the server's
        # legitimate responses to the benign client.

    if not features:
        print("Warning: No valid packets for training were extracted.")
        return pd.DataFrame()
        
    return pd.DataFrame(features, columns=['packet_length', 'label'])

if __name__ == "__main__":
    PCAP_FILE = 'coap_new.pcap' # Assumes this file was generated
    
    print(f"[+] Step 1: Extracting features from '{PCAP_FILE}'...")
    df = extract_features(PCAP_FILE)

    if not df.empty and df['label'].nunique() > 1:
        X = df[['packet_length']]
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        
        print("\n[+] Step 2: Training the Gradient Boosting model...")
        model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
        model.fit(X_train, y_train)
        print("    Model training complete.")

        print("\n[+] Step 3: Evaluating the model...")
        y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print("\n--- Evaluation Results ---")
        print(f"Accuracy:  {accuracy * 100:.2f}%")
        print(f"Precision: {precision:.2f}")
        print(f"Recall:    {recall:.2f}")
        print("--------------------------")
        
        print("\n[+] Step 4: Saving the trained model...")
        joblib.dump(model, 'supervised_model.joblib')
        print("    Model saved to 'supervised_model.joblib'")
    else:
        print("\n[!] Training halted. The dataset is either empty or contains only one class.")


