# Dataset Citation & Data Dictionary

## 1. Dataset Overview
- **Project Domain**: Cybersecurity / Identity and Access Management (IAM)
- **Task**: Binary Classification (Routine Login `0` vs. Suspicious Login `1`)
- **Dataset Size**: 5,000 recorded authentication sessions
- **Class Balance**: 82% Routine (4,100 records), 18% Suspicious (900 records)
- **Timeframe Simulated**: September 2026 enterprise IAM authentication logs

---

## 2. Citation & References

This dataset models real-world authentication behaviors derived from established cybersecurity benchmarks and open datasets on Kaggle:

1. **Kaggle Risk-Based Authentication (RBA) Dataset**:
   - Reference: Wiefling, S., Iacono, L. L., & Markert, P. (2020). *Risk-Based Authentication (RBA) Dataset*. Kaggle / University of Applied Sciences Bonn-Rhein-Sieg.
   - URL: `https://www.kaggle.com/datasets/fredericwiefling/rba-dataset`
   - Description: Empirical study on 33M+ authentication requests measuring IP reputation, device fingerprints, and geolocation hops.

2. **Kaggle User Behaviour & Anomaly Detection**:
   - Reference: *User Behaviour Dataset for Anomaly Detection*. Kaggle Datasets.
   - Focus: Session durations, failed attempt counters, and behavioral deviation from historical baseline.

3. **NIST Special Publication 800-63B**:
   - Reference: National Institute of Standards and Technology (NIST). *Digital Identity Guidelines: Authentication and Lifecycle Management*. NIST SP 800-63B.

---

## 3. Data Dictionary

| Feature Name | Data Type | Units / Format | Description | Normal Baseline | Threat Signal |
|---|---|---|---|---|---|
| `login_id` | String | Identifier | Unique authentication log ID (`LOG-xxxxxx`) | Unique per attempt | Audit trail |
| `timestamp` | Datetime | `YYYY-MM-DD HH:MM:SS` | UTC timestamp of authentication event | Continuous | Temporal audit |
| `login_hour` | Integer | Hour (0 - 23) | Hour of day when login occurred | 08:00 – 21:00 (peak workday) | 01:00 – 05:00 (off-peak bot attacks) |
| `failed_attempts` | Integer | Count (0 - 15+) | Consecutive failed passwords prior to attempt | 0 (85%), 1 (12%), 2 (3%) | 3 to 15+ (brute force / credential stuffing) |
| `session_duration` | Float | Minutes (0.1 - 480.0) | Active session length | 20.0 – 60.0 mins | < 2.0 mins (bot probe) or > 300 mins |
| `device_change_indicator` | Binary | 0 or 1 | 1 if browser/device fingerprint differs from user profile | 0 (92%) | 1 (72% in suspicious events) |
| `location_change_indicator` | Binary | 0 or 1 | 1 if geographical IP / country differs from usual location | 0 (95%) | 1 (78% in impossible travel attacks) |
| `ip_reputation_score` | Float | Risk Index (0.000 - 1.000) | Threat intelligence score (VPN, Tor, Proxy, Botnet) | 0.000 – 0.250 | 0.450 – 0.990 |
| `is_weekend` | Binary | 0 or 1 | 1 if attempt occurred on Saturday or Sunday | Distributed (28%) | Elevated attack activity (45%) |
| `is_suspicious` | Binary | 0 or 1 | **Target Variable**: 0 = Routine Access, 1 = Suspicious Attempt | 82% of records | 18% of records |

---

## 4. Ethical & Privacy Considerations
- **No PII**: All personal identifiers (usernames, raw IP addresses, real names, passwords) have been fully synthesized or stripped to adhere to GDPR, CCPA, and enterprise confidentiality rules.
- **Reproducibility**: Seed fixed at `42` for consistent training, evaluation, and viva demonstration.
