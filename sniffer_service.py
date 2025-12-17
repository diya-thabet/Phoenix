import time
import sqlite3
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict

# 1. LOAD MODELS
print("🧠 Loading AI Models...")
model = joblib.load('xgboost_final.pkl')
scaler = joblib.load('scaler_final.pkl')
le = joblib.load('label_encoder_final.pkl')

# 2. CONFIGURATION
DB_PATH = 'ids_logs.db'
active_flows = defaultdict(list)

# Columns must match training data EXACTLY
COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets', 
    'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

def log_alert(src_ip, dst_ip, src_port, dst_port, attack_type, confidence):
    """Writes the attack to SQLite database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO alerts (src_ip, dst_ip, src_port, dst_port, attack_type, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (src_ip, dst_ip, src_port, dst_port, attack_type, float(confidence)))
        conn.commit()
        conn.close()
        print(f"🚨 LOGGED: {attack_type} from {src_ip}")
    except Exception as e:
        print(f"❌ DB Error: {e}")

def extract_features(flow_key, packets):
    # (Simplified feature extraction logic from previous step)
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = (end_time - start_time) * 1000000 
    
    fwd_pkts = [p for p in packets if p[IP].src == flow_key[0]]
    bwd_pkts = [p for p in packets if p[IP].src == flow_key[1]]
    
    features = {col: 0 for col in COLUMNS}
    
    features['Destination Port'] = flow_key[3] if flow_key[3] else 0
    features['Flow Duration'] = duration
    features['Total Fwd Packets'] = len(fwd_pkts)
    features['Total Backward Packets'] = len(bwd_pkts)
    features['Total Length of Fwd Packets'] = sum(len(p) for p in fwd_pkts)
    features['Total Length of Bwd Packets'] = sum(len(p) for p in bwd_pkts)
    
    return pd.DataFrame([features], columns=COLUMNS)

def process_flow():
    """Analyzes traffic every 3 seconds"""
    while True:
        time.sleep(3)
        current_flows = list(active_flows.items())
        active_flows.clear() # Reset for next batch
        
        if not current_flows: continue
        
        for flow_key, packets in current_flows:
            if len(packets) < 2: continue 

            try:
                # Predict
                df_input = extract_features(flow_key, packets)
                input_scaled = scaler.transform(df_input)
                
                pred_idx = model.predict(input_scaled)[0]
                pred_label = le.inverse_transform([pred_idx])[0]
                
                # If Attack, Save to DB
                if pred_label not in ["BENIGN", "Normal Traffic"]:
                    probs = model.predict_proba(input_scaled)[0]
                    confidence = np.max(probs) * 100
                    
                    src_ip, dst_ip, src_port, dst_port, proto = flow_key
                    log_alert(src_ip, dst_ip, src_port, dst_port, pred_label, confidence)
                    
            except Exception as e:
                pass

def packet_callback(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            src_port, dst_port, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
        else:
            src_port, dst_port, proto = packet[UDP].sport, packet[UDP].dport, "UDP"
            
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        active_flows[flow_key].append(packet)

if __name__ == "__main__":
    import threading
    # Start analysis in background
    t = threading.Thread(target=process_flow)
    t.daemon = True
    t.start()
    
    print("🛡️ Sniffer Service Started (Writing to DB)...")
    sniff(prn=packet_callback, store=0)