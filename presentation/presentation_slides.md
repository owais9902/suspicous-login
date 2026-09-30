# Capstone Presentation: Suspicious Login Behaviour Detection
## Foundational Machine Learning in Zero-Trust Authentication

---

### Slide 1: Title & Capstone Overview
- **Project Title**: Suspicious Login Behaviour Detection
- **Domain**: Cybersecurity / Identity & Access Management (IAM)
- **Task**: Binary Classification (Routine Access vs. Suspicious Access)
- **Architecture**: Zero-Cost Open Source ML Pipeline & Interactive Streamlit Prototype
- **Milestone Duration**: 10 Days End-to-End Implementation

---

### Slide 2: Problem Statement & Motivation
- **The Challenge**: Credential stuffing, password spraying, and Account Takeover (ATO) represent over 60% of web breaches.
- **Limitation of Static Rules**: Hard-coded thresholds ("lock after 5 attempts") are easily bypassed by slow distributed botnets and create unnecessary user lockouts.
- **Objective**: Develop an intelligent, zero-cost behavioral classifier that evaluates authentication telemetry in real time to assign calibrated risk scores.

---

### Slide 3: Telemetry Signals & Threat Indicators
1. **Login Hour (0–23 UTC)**: Identifies off-peak, late-night automated attacks.
2. **Failed Attempts Counter**: Strong indicator of brute-force and credential stuffing.
3. **Session Duration**: Identifies rapid bot scanning (<2 mins) vs normal interactive sessions.
4. **Device Change Indicator**: Flags access from unrecognized browser/OS fingerprints.
5. **Location Change Indicator**: Detects impossible travel and geographic velocity anomalies.
6. **IP Threat Score**: Incorporates SecOps intelligence regarding Tor/VPN/proxy usage.

---

### Slide 4: Dataset Ingestion & Exploratory Analysis
- **Benchmark Source**: Aligned with Kaggle Risk-Based Authentication (RBA) research dataset.
- **Dataset Size**: 5,000 authentication sessions (82% Routine, 18% Suspicious).
- **Key EDA Discoveries**:
  - `failed_attempts`: Correlation of **+0.84** with suspicious logins; mean failed attempts = 5.38 for attacks vs 0.18 for routine logins.
  - `login_hour`: Suspicious logins heavily peak between 01:00 and 05:00 UTC.
  - `device` + `location` change: Combined presence elevates suspicious probability to **94.7%**.

---

### Slide 5: Methodology & Zero-Leakage Pipeline
- **Stratified Partitioning**: 80% Train ($N=4,000$) / 20% Test ($N=1,000$), preserving the 82:18 class ratio.
- **Strict Leakage Prevention**:
  - Scaling transformer (`StandardScaler`) is fitted *exclusively* on the training set.
  - Test set and live production requests are transformed via frozen parameters.
- **Feature Preservation**: Binary signals passed through directly without distortion.

---

### Slide 6: Foundational Model Architectures
- **Logistic Regression**: Linear baseline with L2 regularization and balanced class weighting. Provides calibrated log-odds and sub-millisecond latency.
- **K-Nearest Neighbors (KNN)**: Non-parametric distance-based clustering evaluating behavioral proximity ($k=7$).
- **Decision Tree**: White-box hierarchical splitting rules (`max_depth=5`) providing human-readable explanations.
- **Random Forest (Baseline)**: 100-tree bagging ensemble to benchmark non-linear capacity.

---

### Slide 7: Experimental Results & Benchmarks
| Metric | Logistic Regression | Decision Tree | KNN | Random Forest |
|---|---|---|---|---|
| **Accuracy** | **100.00%** | 99.90% | 100.00% | 100.00% |
| **Precision** | **1.0000** | 0.9945 | 1.0000 | 1.0000 |
| **Recall (Threat)**| **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| **F1-Score** | **1.0000** | 0.9972 | 1.0000 | 1.0000 |
| **ROC-AUC** | **1.0000** | 1.0000 | 1.0000 | 1.0000 |
| **CV F1 (5-Fold)**| **0.9993** | 0.9993 | 0.9993 | 0.9993 |

---

### Slide 8: Cybersecurity Error Analysis & Trade-Offs
- **False Negatives (Security Breach)**:
  - Labeling an attacker as *Routine Access*.
  - Catastrophic: Unchecked corporate intrusion.
  - **Our Result: 0 False Negatives** across all 180 test attack events (100% Recall).
- **False Positives (User Friction)**:
  - Labeling a legitimate user as *Suspicious*.
  - Consequence: Step-Up MFA challenge (OTP prompt).
  - **Our Result: 0 FP in Logistic Regression, 1 FP in Decision Tree**.

---

### Slide 9: Streamlit Application Architecture
- **Interactive UI with 4 Purpose-Built Tabs**:
  1. **Live Risk Inspector**: Sliders and toggles for instant single-event analysis with risk gauge and SecOps actions (Allow, MFA, Block).
  2. **Threat Factor Breakdown**: Natural-language reasoning explaining *why* an event was flagged.
  3. **Batch CSV Scanner**: Ingests bulk enterprise logs, annotates risk scores, and enables CSV export.
  4. **Analytics & Viva Guide**: Embedded performance plots, ROC curves, and capstone defense notes.

---

### Slide 10: Conclusion & Defense Readiness
- **Core Achievement**: Proved foundational ML can reliably protect authentication perimeters at zero infrastructure cost.
- **Key Deliverables**: Complete source code, Jupyter notebook, trained models, academic paper, presentation, and Streamlit prototype.
- **Next Steps**: Continuous behavioral biometrics (keystroke dynamics) and UEBA graph embeddings.
- **Ready for Questions & Viva Defense!**
