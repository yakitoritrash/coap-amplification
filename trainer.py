# trainer.py
from scapy.all import rdpcap, IP, UDP
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import warnings
import os

# Suppress a specific warning from Scapy that is not relevant here
warnings.filterwarnings("ignore", category=UserWarning, module="scapy.layers.inet")

def extract_features(pcap_file, benign_ip='127.0.0.1', victim_ip='192.168.1.100', server_ip='127.0.0.1'):
    """
    Reads a pcap file and extracts features for the ML model.
    It labels packets based on their role in the simulation.
    """
    if not os.path.exists(pcap_file):
        print(f"Error: Pcap file not found at '{pcap_file}'")
        return pd.DataFrame()

    packets = rdpcap(pcap_file)
    features = []
    
    print(f"Processing {len(packets)} packets from {pcap_file}...")
    
    for packet in packets:
        # Ensure the packet has the necessary IP and UDP layers
        if IP not in packet or UDP not in packet:
            continue
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet) # Using total packet length as the primary feature
        
        # --- Labeling Logic ---
        # A request from the benign client to the server is NORMAL (0)
        if src_ip == benign_ip and dst_ip == server_ip:
            label = 0 # Benign
            features.append([pkt_len, label])
            
        # A large response from the server to the spoofed victim is MALICIOUS (1)
        # This is the amplified traffic we want to detect.
        elif src_ip == server_ip and dst_ip == victim_ip:
            label = 1 # Malicious (Attack)
            features.append([pkt_len, label])
            
        # Other packets (e.g., attacker's spoofed requests) are ignored for this specific model
        # as we are focused on detecting the *response* flood at the victim's end.

    if not features:
        print("Warning: No valid CoAP packets were extracted. Check your pcap file and IP configurations.")
        return pd.DataFrame()
        
    return pd.DataFrame(features, columns=['packet_length', 'label'])

# --- Main Execution Block ---
if __name__ == "__main__":
    PCAP_FILE = 'coap_new.pcap'
    
    # 1. Extract features from the captured traffic
    print(f"[+] Step 1: Extracting features from '{PCAP_FILE}'...")
    df = extract_features(PCAP_FILE)

    if df.empty:
        print("[!] Halting execution. Feature extraction failed.")
    else:
        print(f"    Extracted {len(df)} labeled packets.")
        print("    Label distribution:\n", df['label'].value_counts())
        
        # 2. Prepare data for training
        print("\n[+] Step 2: Preparing data for the model...")
        X = df[['packet_length']] # Our feature(s)
        y = df['label']           # Our target (0 or 1)
        
        # Split data into 70% for training and 30% for testing
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        print(f"    Training set size: {len(X_train)}")
        print(f"    Testing set size: {len(X_test)}")

        # 3. Train the Gradient Boosting model (as used in the base paper)
        print("\n[+] Step 3: Training the Gradient Boosting model...")
        # These parameters are standard and robust for this type of problem
        model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
        model.fit(X_train, y_train)
        print("    Model training complete.")

        # 4. Evaluate the model on the unseen test data
        print("\n[+] Step 4: Evaluating the model...")
        y_pred = model.predict(X_test)
        
        # Calculate performance metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print("\n--- Evaluation Results ---")
        print(f"Accuracy:  {accuracy * 100:.2f}%")
        print(f"Precision: {precision:.2f}")
        print(f"Recall:    {recall:.2f}")
        print("--------------------------")
        print("Confusion Matrix:")
        print(f"  TN: {cm[0][0]}  FP: {cm[0][1]}")
        print(f"  FN: {cm[1][0]}  TP: {cm[1][1]}")
        print("--------------------------")

