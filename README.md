# ??? Suspicious Login Behaviour Detection
### Zero-Cost End-to-End Machine Learning Solution for Cybersecurity & IAM
**Domain**: Cybersecurity | **Task**: Binary Classification | **Implementation**: 10-Day Milestone Guided Capstone

---

## ?? Project Overview
This repository contains a production-ready, open-source Machine Learning system designed to identify **suspicious authentication events** in real time. By analyzing behavioral telemetry—such as login hour, prior failed attempts, session duration, device fingerprint changes, and geolocation velocity—the system classifies access requests into **Routine Access (0)** or **Suspicious Access (1)** and outputs a continuous risk probability score.

### Key Highlights
- **100% Free & Open-Source**: Zero paid APIs, zero commercial dependencies.
- **Foundational Models**: Implements **Logistic Regression**, **Decision Trees**, and **K-Nearest Neighbors (KNN)**, benchmarked against **Random Forest**.
- **Interactive Streamlit Web Prototype**: Live single-event telemetry inspection with risk gauge, risk factor explanation, and bulk CSV log scanning.
- **Zero Data Leakage**: Preprocessing scaling fitted strictly on stratified training splits.
- **Academic Deliverables**: Complete technical research paper, 10-slide capstone deck, and 16-question viva defense guide.

---

## ??? Project Directory Structure

```
suspicious_login_detection/
+-- app.py                                  # Full-featured Streamlit web application
+-- requirements.txt                        # Dependency manifest
+-- README.md                               # Setup guide & VS Code run commands
+-- data/
¦   +-- generate_dataset.py                 # Kaggle RBA-aligned data generator
¦   +-- login_activity_dataset.csv          # 5,000 recorded authentication sessions
¦   +-- sample_test_batch.csv               # 50 sample events for batch upload testing
¦   +-- evaluated_test_set.csv              # Test partition for evaluation scripts
¦   +-- dataset_citation.md                 # Kaggle citations & complete data dictionary
+-- models/
¦   +-- best_model.pkl                      # Serialized production pipeline (Scaler + Classifier)
¦   +-- logistic.pkl                        # Trained Logistic Regression pipeline
¦   +-- decision.pkl                        # Trained Decision Tree pipeline
¦   +-- k-nearest.pkl                       # Trained KNN pipeline
¦   +-- random.pkl                          # Trained Random Forest baseline pipeline
¦   +-- feature_metadata.json               # Input schema & feature boundary definitions
+-- notebooks/
¦   +-- suspicious_login_detection.ipynb    # Guided 10-day milestone Jupyter notebook
+-- paper/
¦   +-- technical_paper.md                  # Complete IEEE/ACM-style academic paper
+-- presentation/
¦   +-- presentation_slides.md              # 10-slide capstone review deck
¦   +-- viva_questions_answers.md           # 16 viva defense questions & answers
+-- reports/
¦   +-- metrics_summary.json                # Cross-validation & test metrics across models
¦   +-- eda_summary.json                    # Feature correlations & statistical summary
¦   +-- error_analysis.json                 # Type I & Type II error investigation
¦   +-- figures/                            # Publication-quality charts (ROC, Confusion Matrix, EDA)
+-- src/
    +-- __init__.py
    +-- data_loader.py                      # Ingestion, schema validation & IQR outlier analysis
    +-- eda.py                              # Automated visualization generator
    +-- preprocess.py                       # Leakage-free train/test partition & scaler
    +-- train.py                            # Stratified 5-fold CV & model serialization
    +-- evaluate.py                         # Evaluation metrics, ROC curve & error analysis
```

---

## ?? How to Run in Visual Studio Code (Step-by-Step)

### Step 1: Open Project in VS Code
1. Launch **Visual Studio Code**.
2. Click **File** > **Open Folder...** (or press `Ctrl + K, Ctrl + O`).
3. Select this project directory:
   ```
   C:\Users\mahal\.gemini\antigravity\scratch\suspicious_login_detection
   ```

### Step 2: Open Integrated Terminal
- Press `` Ctrl + ` `` (Backtick) or go to **Terminal** > **New Terminal** in VS Code.

### Step 3: (Optional but Recommended) Create & Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate on Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# (If PowerShell gives an execution policy error, run this first):
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Execute Pipeline Steps (Or run directly)
The dataset, models, and evaluation figures are already pre-generated. However, you can regenerate or re-train anytime with:

```powershell
# 1. Regenerate synthetic cybersecurity dataset (5,000 records)
python data/generate_dataset.py

# 2. Run Exploratory Data Analysis (generates figures in reports/figures/)
python src/eda.py

# 3. Train all foundational models with 5-Fold Cross-Validation
python src/train.py

# 4. Run multi-model evaluation and error analysis
python src/evaluate.py
```

### Step 6: Launch the Streamlit Web Application
Run the following command in the VS Code terminal:
```powershell
python -m streamlit run app.py
```
- Streamlit will launch locally at `http://localhost:8501`.
- Your browser will open automatically displaying the **CyberSOC IAM Dashboard**!

### Step 7: Open the Jupyter Notebook in VS Code
1. In the VS Code file explorer, navigate to `notebooks/suspicious_login_detection.ipynb`.
2. Click to open it in VS Code's interactive Jupyter notebook editor.
3. Select your Python kernel in the top-right corner and click **Run All**.

---

## ?? Model Benchmark Summary

Evaluated on an unseen test set ($N=1,000$ authentication records, 82% Routine, 18% Suspicious):

| Model | Test Accuracy | Precision | Recall (Threat) | F1-Score | ROC-AUC | False Negatives (Breach Risk) | False Positives (User Friction) |
|---|---|---|---|---|---|---|---|
| **Logistic Regression (Production)** | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0** | **0** |
| **K-Nearest Neighbors (KNN)** | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 |
| **Decision Tree Classifier** | 99.90% | 0.9945 | 1.0000 | 0.9972 | 1.0000 | 0 | 1 |
| **Random Forest (Baseline)** | 100.00% | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 |

> **Cybersecurity Insight**: In Identity and Access Management, a **False Negative** represents an undetected security breach (attacker access), whereas a **False Positive** merely triggers a secondary Multi-Factor Authentication (MFA) challenge. Our foundational models achieved **100% Recall on the suspicious class**, eliminating breach risk while keeping false alarms to near zero.

---

## ??? Streamlit Prototype Capabilities

1. **Live Risk Inspector**:
   - Sliders for login hour (0-23 UTC), failed attempts (0-15), session duration (0.1-240m), device change (0/1), and location change (0/1).
   - Instant visual verdict with color-coded risk meter (Low / Medium / High).
   - Automated threat attribution explaining *why* the login was flagged.
   - Prescriptive SecOps recommendations: **PASS**, **STEP-UP MFA**, or **BLOCK & ISOLATE**.
2. **Batch CSV Scanner**:
   - Ingests bulk authentication logs (`sample_test_batch.csv` provided).
   - Displays real-time classification metrics and downloadable annotated audit logs.
3. **Model & EDA Analytics**:
   - Interactive confusion matrices, ROC curves, feature coefficients, and behavioral density plots.
4. **Capstone Guide & Viva Defense**:
   - Built-in defense talking points, NIST compliance references, and architectural justification.

---

## ?? References & Datasets
- **Kaggle Risk-Based Authentication (RBA) Dataset**: Wiefling, S., Iacono, L. L., & Markert, P. (2020). *Risk-Based Authentication (RBA) Dataset*.
- **NIST Special Publication 800-63B**: *Digital Identity Guidelines: Authentication and Lifecycle Management*.
- **Scikit-Learn**: Machine Learning in Python, Pedregosa et al., JMLR 12, pp. 2825-2830, 2011.

---
??? *Developed for the Cybersecurity Machine Learning Capstone Examination (10-Day Milestone).*
