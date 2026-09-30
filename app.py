"""
Suspicious Login Behaviour Detection - Interactive Streamlit Prototype
Author: Cybersecurity Capstone Project
Domain: Identity and Access Management (IAM) & Behavioral Anomaly Detection
"""
import os
import json
import joblib
import pandas as pd
import numpy as np
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="Suspicious Login Detector | CyberSOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1e3a8a;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4b5563;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .verdict-routine {
        background-color: #ecfdf5;
        border: 2px solid #10b981;
        border-radius: 10px;
        padding: 20px;
        color: #065f46;
        text-align: center;
    }
    .verdict-suspicious {
        background-color: #fef2f2;
        border: 2px solid #ef4444;
        border-radius: 10px;
        padding: 20px;
        color: #991b1b;
        text-align: center;
    }
    .risk-badge-low {
        background-color: #10b981;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
    }
    .risk-badge-med {
        background-color: #f59e0b;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
    }
    .risk-badge-high {
        background-color: #ef4444;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_artifacts():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'models', 'best_model.pkl')
    meta_path = os.path.join(base_dir, 'models', 'feature_metadata.json')
    metrics_path = os.path.join(base_dir, 'reports', 'metrics_summary.json')
    
    model = joblib.load(model_path) if os.path.exists(model_path) else None
    
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            metadata = json.load(f)
            
    metrics = {}
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            metrics = json.load(f)
            
    return model, metadata, metrics

model, metadata, metrics = load_artifacts()

# Sidebar
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=70)
st.sidebar.title("CyberSOC IAM")
st.sidebar.markdown("**Task**: Binary Login Classification")
st.sidebar.markdown("**Domain**: Cybersecurity & Zero-Trust")

model_choice = st.sidebar.selectbox(
    "Active ML Classifier",
    ["Logistic Regression (Production)", "Decision Tree", "K-Nearest Neighbors", "Random Forest"]
)

# Load selected model
def get_selected_model(choice):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    mapping = {
        "Logistic Regression (Production)": "logistic.pkl",
        "Decision Tree": "decision.pkl",
        "K-Nearest Neighbors": "k-nearest.pkl",
        "Random Forest": "random.pkl"
    }
    path = os.path.join(base_dir, 'models', mapping.get(choice, 'best_model.pkl'))
    return joblib.load(path) if os.path.exists(path) else model

active_model = get_selected_model(model_choice)

st.sidebar.markdown("---")
st.sidebar.markdown("### Risk Thresholds")
st.sidebar.markdown("- 🟢 **Low Risk**: < 30%\n- 🟡 **Medium Risk**: 30% – 70%\n- 🔴 **High Risk**: > 70%")

# Header
st.markdown('<div class="main-header">🛡️ Suspicious Login Behaviour Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Foundational Machine Learning system evaluating user behavioral telemetry to detect unauthorized access, credential stuffing, and account takeover.</div>', unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Live Risk Inspector", 
    "📂 Batch CSV Detection", 
    "📊 Model Analytics & EDA", 
    "📖 Capstone Guide & Viva"
])

# -------------------------------------------------------------
# TAB 1: LIVE RISK INSPECTOR
# -------------------------------------------------------------
with tab1:
    st.subheader("Single Login Event Inspection")
    st.markdown("Input authentication telemetry to generate an immediate security verdict and risk analysis.")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### Primary Behavioral Telemetry")
        
        login_hour = st.slider(
            "⏰ Login Time (Hour of Day - 24hr UTC)",
            min_value=0, max_value=23, value=14,
            help="Hour when authentication was attempted (0 = Midnight, 14 = 2:00 PM)."
        )
        time_desc = "Daytime Business Hours" if 8 <= login_hour <= 18 else ("Evening / Routine" if 19 <= login_hour <= 22 else "Off-Peak / Late Night (High Risk)")
        st.caption(f"Selected: **{login_hour:02d}:00 UTC** ({time_desc})")
        
        failed_attempts = st.slider(
            "❌ Prior Failed Attempts",
            min_value=0, max_value=15, value=0,
            help="Consecutive incorrect password attempts preceding this login."
        )
        
        session_duration = st.slider(
            "⏱️ Session Duration (Minutes)",
            min_value=0.1, max_value=240.0, value=35.0, step=0.5,
            help="Length of authentication/user session. < 2 mins indicates automated bot scanning."
        )
        
        device_change = st.selectbox(
            "💻 Device Fingerprint Status",
            options=[0, 1],
            format_func=lambda x: "Known / Existing Device (0)" if x == 0 else "New / Unrecognized Device (1)",
            help="Does the browser / user-agent / OS fingerprint match user's historical profile?"
        )
        
        location_change = st.selectbox(
            "📍 Geolocation / IP Country Status",
            options=[0, 1],
            format_func=lambda x: "Standard Geographic Location (0)" if x == 0 else "New Location / Impossible Travel (1)",
            help="Has the user moved to a new country or city within an improbable timeframe?"
        )

    with col2:
        st.markdown("#### Supplementary Risk Signals")
        
        ip_risk = st.slider(
            "🌐 IP Threat Reputation Score",
            min_value=0.0, max_value=1.0, value=0.05, step=0.01,
            help="Threat intelligence score from SecOps (0.0 = Residential Clean, 1.0 = Tor/Bulletproof Proxy)."
        )
        
        is_weekend = st.radio(
            "📅 Day of Week Indicator",
            options=[0, 1],
            format_func=lambda x: "Weekday (Monday - Friday)" if x == 0 else "Weekend (Saturday - Sunday)",
            horizontal=True
        )
        
        st.markdown("---")
        inspect_button = st.button("🚀 Analyze Authentication Event", type="primary", use_container_width=True)

    if inspect_button:
        # Construct input DataFrame with exact features
        input_data = pd.DataFrame([{
            'login_hour': login_hour,
            'failed_attempts': failed_attempts,
            'session_duration': session_duration,
            'device_change_indicator': device_change,
            'location_change_indicator': location_change,
            'ip_reputation_score': ip_risk,
            'is_weekend': is_weekend
        }])
        
        # Inference
        prediction = active_model.predict(input_data)[0]
        if hasattr(active_model, "predict_proba"):
            probabilities = active_model.predict_proba(input_data)[0]
            suspicious_prob = probabilities[1]
        else:
            suspicious_prob = 1.0 if prediction == 1 else 0.0
            
        risk_percentage = round(suspicious_prob * 100, 1)
        
        # Determine Risk Level
        if risk_percentage < 30:
            risk_level = "LOW RISK"
            risk_color = "risk-badge-low"
        elif risk_percentage < 70:
            risk_level = "MEDIUM RISK"
            risk_color = "risk-badge-med"
        else:
            risk_level = "HIGH RISK"
            risk_color = "risk-badge-high"

        st.markdown("---")
        st.markdown("### 📋 Security Assessment Verdict")
        
        res_col1, res_col2 = st.columns([1, 1])
        
        with res_col1:
            if prediction == 0:
                st.markdown(f"""
                <div class="verdict-routine">
                    <h2>✅ ROUTINE LOGIN</h2>
                    <p style="font-size: 1.1rem; margin-top: 8px;">Authentication patterns match normal baseline behavior.</p>
                    <span class="{risk_color}">{risk_level} ({risk_percentage}%)</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="verdict-suspicious">
                    <h2>🚨 SUSPICIOUS LOGIN DETECTED</h2>
                    <p style="font-size: 1.1rem; margin-top: 8px;">Anomalous access signals detected. Threat score exceeded baseline.</p>
                    <span class="{risk_color}">{risk_level} ({risk_percentage}%)</span>
                </div>
                """, unsafe_allow_html=True)
                
            st.markdown(f"**Predicted Class**: `{prediction}` ({'Routine' if prediction==0 else 'Suspicious'})")
            st.progress(suspicious_prob, text=f"Threat Probability: {risk_percentage}%")

        with res_col2:
            st.markdown("#### 🧠 Risk Factor Breakdown & Threat Reasoning")
            risk_factors = []
            
            if failed_attempts >= 3:
                risk_factors.append(f"🔴 **Multiple Failed Logins ({failed_attempts})**: High likelihood of brute force or credential stuffing.")
            elif failed_attempts > 0:
                risk_factors.append(f"🟡 **Minor Failed Logins ({failed_attempts})**: Normal typo or low-severity anomaly.")
                
            if device_change == 1:
                risk_factors.append("🔴 **New Device Fingerprint**: Session initiated from unrecognized browser/OS profile.")
                
            if location_change == 1:
                risk_factors.append("🔴 **Geographic Velocity Anomaly**: Location difference signals possible impossible travel or proxy hop.")
                
            if login_hour in [1, 2, 3, 4, 5]:
                risk_factors.append(f"🔴 **Off-Peak Access ({login_hour:02d}:00 UTC)**: Typical timeframe for automated bot operations.")
                
            if ip_risk >= 0.5:
                risk_factors.append(f"🔴 **Elevated IP Risk ({ip_risk:.2f})**: IP address flagged in threat intelligence feeds (Tor/VPN/Botnet).")
                
            if session_duration < 2.0:
                risk_factors.append(f"🟡 **Extremely Brief Session ({session_duration}m)**: Consistent with automated script reconnaissance.")
                
            if not risk_factors:
                st.success("🟢 No anomalous risk factors detected. Session exhibits standard user telemetry.")
            else:
                for rf in risk_factors:
                    st.markdown(rf)

            st.markdown("#### 🔐 SecOps Action Recommendation")
            if prediction == 0 and risk_percentage < 30:
                st.info("**ACTION: PASS** — Allow session without user friction. Log event for standard audit.")
            elif risk_percentage < 70:
                st.warning("**ACTION: STEP-UP MFA** — Prompt user for secondary Multi-Factor Authentication (OTP / Hardware Token).")
            else:
                st.error("**ACTION: BLOCK & ISOLATE** — Terminate session immediately, force credential reset, and dispatch alert to SOC tier 1.")

# -------------------------------------------------------------
# TAB 2: BATCH CSV DETECTION
# -------------------------------------------------------------
with tab2:
    st.subheader("Batch Authentication Log Scanner")
    st.markdown("Upload bulk authentication records in CSV format to classify multiple events simultaneously.")
    
    st.download_button(
        label="📥 Download Sample Batch CSV (50 Records)",
        data=open('data/sample_test_batch.csv', 'r').read() if os.path.exists('data/sample_test_batch.csv') else "",
        file_name="sample_test_batch.csv",
        mime="text/csv"
    )
    
    uploaded_file = st.file_uploader("Upload Authentication Log CSV", type=["csv"])
    
    if uploaded_file is not None:
        batch_df = pd.read_csv(uploaded_file)
        st.write(f"Loaded **{len(batch_df)}** records.")
        st.dataframe(batch_df.head(5), use_container_width=True)
        
        # Verify required columns
        req_cols = ['login_hour', 'failed_attempts', 'session_duration', 'device_change_indicator', 'location_change_indicator']
        missing = [c for c in req_cols if c not in batch_df.columns]
        
        if missing:
            st.error(f"Missing mandatory columns: {missing}")
        else:
            if st.button("⚡ Run Batch Risk Classification", type="primary"):
                # Fill missing optional columns if needed
                if 'ip_reputation_score' not in batch_df.columns:
                    batch_df['ip_reputation_score'] = 0.05
                if 'is_weekend' not in batch_df.columns:
                    batch_df['is_weekend'] = 0
                    
                preds = active_model.predict(batch_df)
                probs = active_model.predict_proba(batch_df)[:, 1] if hasattr(active_model, "predict_proba") else preds
                
                results_df = batch_df.copy()
                results_df['predicted_class'] = preds
                results_df['threat_label'] = ['Suspicious' if p == 1 else 'Routine' for p in preds]
                results_df['risk_probability'] = probs.round(4)
                results_df['risk_level'] = ['HIGH' if p >= 0.7 else ('MEDIUM' if p >= 0.3 else 'LOW') for p in probs]
                
                # Metrics summary
                suspicious_count = int((preds == 1).sum())
                routine_count = int((preds == 0).sum())
                
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Scanned", len(results_df))
                m2.metric("Routine Events", routine_count)
                m3.metric("Suspicious Flagged", suspicious_count, delta=f"{(suspicious_count/len(results_df))*100:.1f}%")
                m4.metric("Avg Threat Probability", f"{probs.mean()*100:.1f}%")
                
                st.markdown("#### Scanned Results Table")
                st.dataframe(
                    results_df.style.map(
                        lambda v: 'background-color: #fee2e2; color: #991b1b; font-weight: bold;' if v == 'Suspicious' else '',
                        subset=['threat_label']
                    ),
                    use_container_width=True
                )
                
                # Download enriched CSV
                csv_data = results_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="💾 Export Classified Security Audit Log (CSV)",
                    data=csv_data,
                    file_name="classified_login_security_audit.csv",
                    mime="text/csv",
                    type="secondary"
                )

# -------------------------------------------------------------
# TAB 3: MODEL ANALYTICS & EDA
# -------------------------------------------------------------
with tab3:
    st.subheader("Model Performance & Behavioral Telemetry Analytics")
    
    # Quantitative comparison table
    if metrics:
        st.markdown("#### 1. Foundational Model Benchmark (N=1,000 Test Set)")
        table_rows = []
        for m_name, vals in metrics.items():
            table_rows.append({
                'Classifier': m_name,
                'Accuracy': f"{vals['test_accuracy']*100:.2f}%",
                'Precision': f"{vals['test_precision']:.4f}",
                'Recall (Sensitivity)': f"{vals['test_recall']:.4f}",
                'F1-Score': f"{vals['test_f1_score']:.4f}",
                'ROC-AUC': f"{vals['test_roc_auc']:.4f}",
                'Breach Risk (FN)': vals['confusion_matrix']['false_negatives_breach'],
                'User Friction (FP)': vals['confusion_matrix']['false_positives_friction']
            })
        st.table(pd.DataFrame(table_rows))
        st.caption("Key insight: Both foundational models achieve high precision and recall, with Logistic Regression providing calibrated log-odds.")

    st.markdown("---")
    st.markdown("#### 2. Evaluation Visualizations")
    vcol1, vcol2 = st.columns(2)
    
    with vcol1:
        if os.path.exists("reports/figures/roc_curves_comparison.png"):
            st.image("reports/figures/roc_curves_comparison.png", caption="ROC-AUC Multi-Model Curve Comparison")
        if os.path.exists("reports/figures/confusion_matrix_comparison.png"):
            st.image("reports/figures/confusion_matrix_comparison.png", caption="Confusion Matrix Grid Across Classifiers")
            
    with vcol2:
        if os.path.exists("reports/figures/feature_importance.png"):
            st.image("reports/figures/feature_importance.png", caption="Feature Coefficients & Gini Importance")
        if os.path.exists("reports/figures/correlation_heatmap.png"):
            st.image("reports/figures/correlation_heatmap.png", caption="Feature Correlation Matrix")

    st.markdown("---")
    st.markdown("#### 3. Exploratory Behavioral Patterns")
    ecol1, ecol2 = st.columns(2)
    with ecol1:
        if os.path.exists("reports/figures/login_hour_density.png"):
            st.image("reports/figures/login_hour_density.png", caption="Temporal Density: Login Hour Distribution")
        if os.path.exists("reports/figures/failed_attempts_dist.png"):
            st.image("reports/figures/failed_attempts_dist.png", caption="Failed Login Attempt Frequency by Category")
            
    with ecol2:
        if os.path.exists("reports/figures/device_location_risk.png"):
            st.image("reports/figures/device_location_risk.png", caption="Threat Probability by Device & Location Changes")
        if os.path.exists("reports/figures/session_duration_box.png"):
            st.image("reports/figures/session_duration_box.png", caption="Session Duration Boxplot (Log Scale)")

# -------------------------------------------------------------
# TAB 4: CAPSTONE GUIDE & VIVA PREPARATION
# -------------------------------------------------------------
with tab4:
    st.subheader("Capstone Project Defense & Viva Cheat Sheet")
    st.markdown("""
    This section summarizes key architectural decisions and provides answers to common defense questions.
    """)
    
    with st.expander("📌 1. Why use Foundational Models instead of Deep Learning?"):
        st.write("""
        **Response**:
        1. **Interpretability & Auditability**: In enterprise cybersecurity and compliance (GDPR/NIST), decisions that lock out users or block access must be explainable. Logistic Regression provides direct log-odds, and Decision Trees offer explicit if-then branch logic.
        2. **Latency & Zero-Cost Compute**: Foundational models infer predictions in sub-millisecond speeds (< 2ms), making them ideal for high-throughput authentication gateways (e.g. Okta, Keycloak) without requiring expensive GPU infrastructure.
        3. **Sample Efficiency**: Tabular behavioral telemetry does not require complex deep neural representations; structured feature engineering yields near-optimal ROC-AUC with foundational classifiers.
        """)
        
    with st.expander("🛡️ 2. What is the difference between False Positives and False Negatives in IAM?"):
        st.write("""
        **Response**:
        - **False Negative (Type II Error - Security Breach)**: The system predicts *Routine Access* when an attacker is actually breaching the account (e.g. credential stuffing). This is catastrophic as unauthorized data exfiltration or privilege escalation can occur.
        - **False Positive (Type I Error - User Friction)**: The system predicts *Suspicious Access* for a legitimate employee (e.g., someone working from an airport hotel on a new laptop). This results in a step-up MFA challenge or temporary prompt. While annoying, it does not breach data.
        - **Objective**: We tune our models to maximize **Recall on the Suspicious Class** to drive False Negatives as close to zero as possible.
        """)

    with st.expander("📊 3. How did you prevent Data Leakage?"):
        st.write("""
        **Response**:
        1. **Stratified Split Before Scaling**: The dataset was split into 80% train and 20% test using `StratifiedKFold` *before* applying any preprocessing transformations.
        2. **Pipeline Encapsulation**: `StandardScaler` was fitted strictly on `X_train`. The test set and real-time Streamlit inputs are transformed using the pre-fitted transformer, ensuring zero leakage of test distribution statistics.
        """)

    with st.expander("⏱️ 4. What are the 10-Day Milestones completed in this project?"):
        st.write("""
        - **D1 (Research)**: Threat modeling, IAM literature review, NIST SP 800-63B standards.
        - **D2 (Data)**: Ingestion, schema validation, Kaggle RBA benchmark synthesis.
        - **D3 (EDA)**: Correlation heatmaps, class balance, temporal and IQR outlier analysis.
        - **D4 (Model)**: Logistic Regression, Decision Tree, KNN, and Random Forest implementations.
        - **D5 (Evaluation)**: ROC-AUC, Precision-Recall curves, confusion matrices, and log-loss.
        - **D6 (Improvement)**: Hyperparameter tuning and decision threshold calibration.
        - **D7 (App)**: Interactive Streamlit prototype with live inspector and batch scanning.
        - **D8 (Integration)**: Serialization of scikit-learn pipelines and schema validators.
        - **D9 (Paper/PPT)**: Academic technical paper, 10-slide deck, and viva questions.
        - **D10 (Demo/Viva)**: Complete end-to-end reproducible prototype packaging and defense.
        """)

st.markdown("---")
st.caption("🛡️ Suspicious Login Behaviour Detection Capstone | Zero-Cost Open Source ML Solution | 2026")
