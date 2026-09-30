# Cybersecurity Capstone Viva Defense: Questions & Detailed Technical Answers

This guide prepares you to confidently explain, defend, and justify every architectural, mathematical, and cybersecurity decision made throughout this capstone project.

---

### Q1: What is the core problem statement of this project?
**Answer**:
The objective is to identify authentication events that exhibit patterns associated with unauthorized or suspicious access (such as brute force, credential stuffing, and account takeover) using foundational machine learning algorithms. The model ingests contextual behavioral signals—login time, failed attempts, session duration, device indicators, and location changes—and outputs a binary classification verdict (Routine vs. Suspicious) along with a calibrated risk probability score.

---

### Q2: Why did you choose Foundational Models (Logistic Regression, Decision Trees, KNN) over Deep Learning?
**Answer**:
1. **Explainability & Compliance**: In cybersecurity and privacy regulations (such as GDPR Article 22 and NIST SP 800-63B), automated decisions that deny service or demand extra authentication must be auditable. Logistic Regression provides exact log-odds coefficients, and Decision Trees provide human-readable branch rules.
2. **Sub-Millisecond Latency**: Authentication gateways process millions of logins per day. Logistic Regression computes predictions in under 1 millisecond on standard CPUs, eliminating the need for expensive GPU inference servers.
3. **Tabular Efficiency**: Behavioral telemetry is structured tabular data where foundational models combined with robust feature engineering match or exceed deep learning performance while avoiding overfitting.

---

### Q3: How did you prevent Data Leakage during the preprocessing phase?
**Answer**:
Data leakage occurs when information from outside the training dataset is inadvertently used to create the model. We prevented it through:
1. **Stratified Split First**: We partitioned the dataset into 80% train and 20% test *prior* to calculating any summary statistics or scalers.
2. **Scikit-Learn ColumnTransformer / Pipeline**: The `StandardScaler` was fitted strictly on `X_train`. The test partition and real-time inference inputs are transformed using the saved mean and variance parameters from the training set without refitting.

---

### Q4: What is the significance of the 82:18 Class Imbalance, and how did you handle it?
**Answer**:
In enterprise IAM environments, legitimate logins vastly outnumber malicious attacks; hence, an 82% routine to 18% suspicious distribution reflects real-world operational security data. To address this:
1. We utilized `StratifiedKFold` and stratified `train_test_split` to ensure both train and test splits preserve the 82:18 ratio.
2. We configured `class_weight='balanced'` in Logistic Regression and Decision Tree, which automatically adjusts loss penalties inversely proportional to class frequencies, ensuring the model does not bias toward the majority routine class.
3. We evaluated performance using **Precision, Recall, F1-Score, and ROC-AUC** rather than relying solely on raw Accuracy.

---

### Q5: In Cybersecurity, what is the trade-off between False Positives and False Negatives? Which is worse?
**Answer**:
- **False Negative (Type II Error - Security Breach)**: Predicting *Routine* when the access is actually *Suspicious*. This is by far the most dangerous outcome, as an attacker bypasses defenses, leading to unauthorized data exfiltration or privilege escalation.
- **False Positive (Type I Error - User Friction)**: Predicting *Suspicious* when the login is actually a legitimate user. In modern Zero-Trust systems, a false positive does not mean an outright account lock; instead, it triggers a **Step-Up MFA challenge** (sending an OTP or push prompt to the user's phone).
- **Strategy**: We prioritize **Recall on the Suspicious Class** to drive False Negatives to zero, while maintaining high Specificity to minimize unnecessary user friction.

---

### Q6: Why did Logistic Regression achieve near-perfect performance on this dataset?
**Answer**:
Cybersecurity behavioral signals (especially high failed attempts, sudden impossible travel hops, and known malicious IP reputations) create strong, well-separated directional signals in log-odds space. Because L2 regularization was applied and continuous variables were standardized, the linear decision boundary cleanly separates the clusters without overfitting.

---

### Q7: What are the primary attack vectors your system detects?
**Answer**:
1. **Brute Force & Credential Stuffing**: Identified by spikes in `failed_attempts` ($\ge 3$) coupled with new devices.
2. **Impossible Travel / Geolocation Velocity**: Flagged by `location_change_indicator == 1`.
3. **Automated Bot Probes**: Identified by off-peak hours (01:00–05:00 UTC) combined with abnormally short session lengths ($< 2.0$ minutes).
4. **Anomalous Devices / Account Takeover**: Triggered when access originates from an unknown browser/OS canvas fingerprint (`device_change_indicator == 1`).

---

### Q8: How does your Streamlit prototype handle new, unseen inputs?
**Answer**:
The Streamlit application imports the serialized `best_model.pkl` pipeline. When a user adjusts the sliders or uploads a CSV file:
1. Input values are validated against schema bounds defined in `models/feature_metadata.json`.
2. The pipeline's embedded `ColumnTransformer` automatically standardizes the numerical features using the frozen training parameters.
3. The model outputs a binary prediction (`0` or `1`) and a continuous probability score (`predict_proba`).
4. The application translates the probability into risk tiers (Low <30%, Medium 30-70%, High >70%), generates a human-readable threat factor breakdown, and recommends a specific SecOps action (Pass, Step-Up MFA, Block).

---

### Q9: What role does IQR (Interquartile Range) play in your data quality analysis?
**Answer**:
In `src/data_loader.py`, we calculate IQR ($Q3 - Q1$) to identify statistical outliers. For `failed_attempts`, the upper IQR threshold is 2.5 attempts; values exceeding this boundary accounted for 15.36% of the dataset, matching the suspicious class profile. This confirmed that outlier detection directly correlates with adversarial behavior.

---

### Q10: How would you deploy this solution into a live enterprise authentication flow?
**Answer**:
In production, this ML pipeline would be packaged as a lightweight REST or gRPC microservice sitting directly behind the enterprise Identity Provider (IdP) such as Okta, Keycloak, or PingFederate:
1. During the initial authentication phase (username + password submission), telemetry is collected by the login page SDK.
2. The IdP fires an asynchronous or sub-5ms synchronous webhook to the classifier.
3. If risk score is < 30%, session token is issued seamlessly (Frictionless SSO).
4. If risk score is between 30% and 70%, the IdP triggers Step-Up MFA (FIDO2 WebAuthn / OTP).
5. If risk score is > 70%, the attempt is blocked and a security alert is forwarded to the enterprise SIEM/SOAR system.

---

### Q11: What are the limitations of this model?
**Answer**:
1. **Adversarial Adaptation**: Attackers using distributed residential proxies and "low-and-slow" password spraying (1 attempt per day) may evade simple count-based thresholds.
2. **Cold-Start Problem**: New users without an established baseline history may trigger step-up MFA until sufficient routine behavior is recorded.
3. **Synthetic Telemetry**: While modeled on real-world RBA research distributions, live enterprise environments exhibit greater noise and seasonal drift.

---

### Q12: How would you extend this project in the future?
**Answer**:
1. **Continuous Authentication**: Transition from single-point-in-time login inspection to continuous session monitoring using keystroke dynamics and mouse movement patterns.
2. **Graph Neural Networks (GNNs)**: Model entity-relationship graphs linking users, devices, IP subnets, and organizational permissions to detect coordinated insider threats.
3. **Online Adaptive Learning**: Implement incremental learning (e.g., SGDClassifier) to adaptively update model weights as employee travel and working habits evolve.

---

### Q13: Can you explain how you verified that the solution operates at zero cost?
**Answer**:
The entire architecture relies exclusively on free, open-source technologies: Python 3.13, Scikit-learn, Pandas, NumPy, Matplotlib, Seaborn, and Streamlit. No commercial APIs, paid cloud services, or proprietary software licenses are required.

---

### Q14: What is ROC-AUC and why is it preferred over raw Accuracy?
**Answer**:
Receiver Operating Characteristic - Area Under the Curve (ROC-AUC) measures the classifier's ability to discriminate between positive (suspicious) and negative (routine) classes across all possible decision thresholds from 0.0 to 1.0. Unlike raw Accuracy, which can be deceptively high in imbalanced datasets by simply predicting the majority class, ROC-AUC is threshold-independent and evaluates the true trade-off between sensitivity (Recall) and false alarm rate.

---

### Q15: How does your project meet the 10-Day Milestones outlined in the rubric?
**Answer**:
- **D1 (Research)**: Defined threat model and RBA literature.
- **D2 (Data)**: Kaggle RBA benchmark synthesis and data dictionary creation.
- **D3 (EDA)**: Correlation heatmaps, class distributions, and IQR outlier detection.
- **D4 (Model)**: Logistic Regression, KNN, Decision Tree, and Random Forest baselines.
- **D5 (Evaluation)**: 5-Fold Stratified Cross-Validation, ROC curves, and confusion matrices.
- **D6 (Improvement)**: Hyperparameter tuning and zero-leakage pipeline design.
- **D7 (App)**: Interactive Streamlit application with single-event and batch inspection.
- **D8 (Integration)**: Model serialization and schema validation.
- **D9 (Paper/PPT)**: Academic technical paper, slide presentation, and defense guide.
- **D10 (Demo/Viva)**: Complete end-to-end reproducible prototype packaging and defense.

---

### Q16: If you could change one feature in your dataset, what would it be?
**Answer**:
I would incorporate **Historical User Entropy**—a numerical metric quantifying how frequently an individual user deviates from their personal baseline. In our current model, telemetry is evaluated against global population baselines. Incorporating individual user baselines would enable even more precise personalization and further reduce false-positive MFA prompts.
