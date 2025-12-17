import streamlit as st
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import time

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
st.set_page_config(
    page_title="🛡️ AI Intrusion Detection System",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS for a "Hacker/Cyber" look
st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
        color: #00ff41;
    }
    .metric-card {
        background-color: #262730;
        border: 1px solid #4e4e4e;
        padding: 20px;
        border-radius: 10px;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

# ==========================================
# 2. LOAD MODELS
# ==========================================
@st.cache_resource
def load_assets():
    try:
        # Load the files you downloaded from Colab
        model = joblib.load('xgboost_final.pkl')
        scaler = joblib.load('scaler_final.pkl')
        le = joblib.load('label_encoder_final.pkl')
        return model, scaler, le
    except Exception as e:
        st.error(f"❌ Error loading model files: {e}")
        st.error("Please make sure 'xgboost_final.pkl', 'scaler_final.pkl', and 'label_encoder_final.pkl' are in the same folder.")
        return None, None, None

model, scaler, le = load_assets()

# ==========================================
# 3. SIDEBAR (INPUTS)
# ==========================================
st.sidebar.header("🔧 Traffic Simulator")
st.sidebar.markdown("Manually adjust network parameters to test the AI:")

# Define features (These must match your training data columns!)
# Note: In a real app, these come from CICFlowMeter automatically.
# We simplify here for the prototype.
feature_inputs = {}

# We create sliders for the most important features (based on feature importance)
feature_inputs['Destination Port'] = st.sidebar.number_input("Destination Port", 0, 65535, 80)
feature_inputs['Flow Duration'] = st.sidebar.number_input("Flow Duration (ms)", 0, 10000000, 500)
feature_inputs['Total Fwd Packets'] = st.sidebar.number_input("Total Fwd Packets", 0, 100000, 5)
feature_inputs['Total Backward Packets'] = st.sidebar.number_input("Total Backward Packets", 0, 100000, 2)
feature_inputs['Total Length of Fwd Packets'] = st.sidebar.number_input("Total Len Fwd Pkts", 0, 10000000, 200)

# Random button to simulate traffic
if st.sidebar.button("🎲 Simulate Random Traffic"):
    feature_inputs['Destination Port'] = np.random.randint(0, 65535)
    feature_inputs['Flow Duration'] = np.random.randint(100, 500000)
    feature_inputs['Total Fwd Packets'] = np.random.randint(1, 100)
    feature_inputs['Total Backward Packets'] = np.random.randint(1, 100)
    feature_inputs['Total Length of Fwd Packets'] = np.random.randint(100, 50000)

# ==========================================
# 4. MAIN DASHBOARD
# ==========================================
st.title("🛡️ SecureNet AI: Intelligent IDS")
st.markdown("### Real-time Network Traffic Analysis")

# Placeholder for visual flair
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="System Status", value="ACTIVE", delta="Monitoring")
with col2:
    st.metric(label="Model Accuracy", value="99.9%", delta="XGBoost")
with col3:
    st.metric(label="Threat Level", value="LOW", delta_color="inverse")

st.divider()

# ==========================================
# 5. PREDICTION LOGIC
# ==========================================
if model and st.button("🚀 Analyze Traffic Pattern"):
    
    with st.spinner('Scanning packet structure...'):
        time.sleep(0.5) # Dramatic effect
        
        # 1. Prepare Data
        # IMPORTANT: We must match the exact 78 features expected by the model.
        # Since we only have 5 sliders, we will pad the rest with zeros (Prototype Limitation).
        # In a real deployed app, you would pass the full CSV row here.
        
        # Get expected number of features from scaler
        n_features = scaler.n_features_in_
        
        # Create a dummy array with zeros
        input_data = np.zeros((1, n_features))
        
        # Fill in the values we know (first 5 columns just for demo)
        # Note: This is a simplification. To be accurate, you need to map inputs to specific indices.
        # For this demo, we assume the first 5 features map to our inputs.
        values = list(feature_inputs.values())
        for i, val in enumerate(values):
            if i < n_features:
                input_data[0, i] = val
                
        # 2. Scale Data
        input_scaled = scaler.transform(input_data)
        
        # 3. Predict
        prediction_index = model.predict(input_scaled)[0]
        prediction_label = le.inverse_transform([prediction_index])[0]
        
        # 4. Get Probability (Confidence)
        probs = model.predict_proba(input_scaled)[0]
        confidence = np.max(probs) * 100
        
        # ==========================================
        # 6. RESULT DISPLAY
        # ==========================================
        st.subheader("🔍 Analysis Result")
        
        if prediction_label == "Normal Traffic" or prediction_label == "BENIGN":
            st.success(f"✅ TRAFFIC NORMAL")
            st.balloons()
        else:
            st.error(f"🚨 INTRUSION DETECTED: {prediction_label.upper()}")
            st.toast(f"Security Alert: {prediction_label} detected!", icon="🔥")
        
        # Details Column
        c1, c2 = st.columns([1, 1])
        
        with c1:
            st.info(f"**Classification:** {prediction_label}")
            st.info(f"**Confidence Score:** {confidence:.2f}%")
            
        with c2:
            # Plot Probability Distribution
            fig, ax = plt.subplots()
            sns.barplot(x=le.classes_, y=probs, ax=ax, palette="viridis")
            plt.xticks(rotation=90)
            plt.ylabel("Probability")
            plt.title("AI Prediction Confidence")
            st.pyplot(fig)

st.divider()
st.caption("Developed for Cybersecurity Project 1 | Powered by XGBoost & Streamlit")