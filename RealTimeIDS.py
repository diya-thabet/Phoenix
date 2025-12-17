import time
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import joblib
import os
from collections import defaultdict
import threading

# ==========================================
# CONFIGURATION
# ==========================================
# 1. Load your trained "Brains"
print("🧠 Loading AI Model...")
model = joblib.load('xgboost_final.pkl')
scaler = joblib.load('scaler_final.pkl')
le = joblib.load('label_encoder_final.pkl')

# 2. Define the Columns (Must match your training data EXACTLY)
# These are the standard CICIDS2017 features. 
# We will calculate the important ones and set others to 0.
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

# Flow Storage (To hold incomplete conversations)
active_flows = defaultdict(list)

def extract_features(flow_key, packets):
    """
    Turns a list of raw packets into a single row of numbers (Features)
    """
    # Basic Stats
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = (end_time - start_time) * 1000000 # Microseconds
    
    fwd_pkts = [p for p in packets if p[IP].src == flow_key[0]]
    bwd_pkts = [p for p in packets if p[IP].src == flow_key[1]]
    
    # Feature Vector (Initialize with 0s)
    features = {col: 0 for col in COLUMNS}
    
    # Fill KEY features (The ones that matter most)
    features['Destination Port'] = flow_key[3] if flow_key[3] else 0
    features['Flow Duration'] = duration
    features['Total Fwd Packets'] = len(fwd_pkts)
    features['Total Backward Packets'] = len(bwd_pkts)
    features['Total Length of Fwd Packets'] = sum(len(p) for p in fwd_pkts)
    features['Total Length of Bwd Packets'] = sum(len(p) for p in bwd_pkts)
    
    # Calculate Flow Bytes/s
    total_bytes = features['Total Length of Fwd Packets'] + features['Total Length of Bwd Packets']
    if duration > 0:
        features['Flow Bytes/s'] = (total_bytes / duration) * 1000000
        features['Flow Packets/s'] = (len(packets) / duration) * 1000000

    # Return as DataFrame row
    return pd.DataFrame([features], columns=COLUMNS)

def process_flow():
    """
    Background task: Checks active flows every 3 seconds, predicts, and clears them.
    """
    global active_flows
    while True:
        time.sleep(3) # Wait for packets to accumulate
        
        # Make a copy to avoid errors while modifying
        current_flows = list(active_flows.items())
        
        if not current_flows:
            continue
            
        print(f"🔍 Analyzing {len(current_flows)} active flows...")
        
        for flow_key, packets in current_flows:
            if len(packets) < 2: continue # Ignore single packets (noise)

            try:
                # 1. Extract Features
                df_input = extract_features(flow_key, packets)
                
                # 2. Scale (Normalize)
                # IMPORTANT: We only scale the columns the model expects
                input_scaled = scaler.transform(df_input)
                
                # 3. Predict
                pred_idx = model.predict(input_scaled)[0]
                pred_label = le.inverse_transform([pred_idx])[0]
                
                # 4. Alert
                src_ip, dst_ip, src_port, dst_port, proto = flow_key
                if pred_label != "BENIGN" and pred_label != "Normal Traffic":
                    print(f"🚨 [ALERT] {pred_label} Detected!")
                    print(f"   Source: {src_ip}:{src_port} -> Dest: {dst_ip}:{dst_port}")
                else:
                    # Optional: Print benign traffic just to show it's working
                    # print(f"✅ Normal: {src_ip} -> {dst_ip}")
                    pass
                    
            except Exception as e:
                pass # Skip broken flows
                
        # Clear processed flows to save memory
        active_flows.clear()

def packet_callback(packet):
    """
    Called for EVERY packet sniffing catches.
    Groups them into flows by IP/Port.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Handle TCP/UDP Ports
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto = "UDP"
        else:
            return # Ignore non-TCP/UDP for now

        # Create a unique ID for this conversation
        # (Src IP, Dst IP, Src Port, Dst Port, Protocol)
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        
        # Store packet
        active_flows[flow_key].append(packet)

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print("🛡️ Real-Time IDS Initialized.")
    print("   Mode: Sniffing Network Interface...")
    
    # Start the Analysis Thread (The "Brain")
    analysis_thread = threading.Thread(target=process_flow)
    analysis_thread.daemon = True
    analysis_thread.start()
    
    # Start Sniffing (The "Ears")
    # iface=None will sniff the default interface (WiFi or Ethernet)
    print("👂 Listening for traffic... (Press Ctrl+C to stop)")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopping IDS.")