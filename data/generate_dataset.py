import os
import numpy as np
import pandas as pd

np.random.seed(42)

def generate_login_data(n_samples=5000, suspicious_ratio=0.18):
    n_suspicious = int(n_samples * suspicious_ratio)
    n_routine = n_samples - n_suspicious

    # --- Routine Login Patterns ---
    # Normal hours: Peak around 9 AM to 8 PM (mixture of normal working day)
    routine_hours = np.clip(np.random.normal(loc=13.5, scale=4.0, size=n_routine).astype(int), 0, 23)
    
    # Routine failed attempts: mostly 0 (85%), 1 (12%), 2 (3%)
    routine_failed = np.random.choice([0, 1, 2], size=n_routine, p=[0.85, 0.12, 0.03])
    
    # Routine session duration (minutes): log-normal around 35 mins
    routine_duration = np.clip(np.random.lognormal(mean=3.2, sigma=0.6, size=n_routine), 2.0, 360.0).round(1)
    
    # Routine device change: mostly 0 (same device ~92%, new device ~8%)
    routine_device_change = np.random.choice([0, 1], size=n_routine, p=[0.92, 0.08])
    
    # Routine location change: mostly 0 (~95%, travel/telework ~5%)
    routine_location_change = np.random.choice([0, 1], size=n_routine, p=[0.95, 0.05])
    
    # Routine IP reputation score: low risk (0.0 to 0.25)
    routine_ip_risk = np.clip(np.random.beta(a=1.2, b=12.0, size=n_routine), 0.0, 0.35).round(3)
    
    # Routine weekend indicator: ~25% on weekend
    routine_weekend = np.random.choice([0, 1], size=n_routine, p=[0.72, 0.28])

    df_routine = pd.DataFrame({
        'login_hour': routine_hours,
        'failed_attempts': routine_failed,
        'session_duration': routine_duration,
        'device_change_indicator': routine_device_change,
        'location_change_indicator': routine_location_change,
        'ip_reputation_score': routine_ip_risk,
        'is_weekend': routine_weekend,
        'is_suspicious': 0
    })

    # --- Suspicious Login Patterns ---
    # Attack vectors:
    # 1. Brute-force / Credential stuffing: High failed attempts, new device/location
    # 2. Impossible travel / Account Takeover: Location change, high IP risk, unusual hour
    # 3. Automated fast bot probing: Extremely short duration (0-2 mins), off-peak hour (1-5 AM)
    
    # Suspicious hours: more prevalent late night / off-peak (0-5 AM) and spread out
    suspicious_hours = np.random.choice(
        [0, 1, 2, 3, 4, 5, 6, 12, 18, 22, 23], 
        size=n_suspicious, 
        p=[0.14, 0.16, 0.16, 0.14, 0.10, 0.06, 0.04, 0.04, 0.04, 0.06, 0.06]
    )
    
    # Suspicious failed attempts: 2 to 14 failures
    suspicious_failed = np.random.choice(
        [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15],
        size=n_suspicious,
        p=[0.05, 0.08, 0.15, 0.18, 0.16, 0.12, 0.10, 0.07, 0.04, 0.03, 0.02]
    )
    
    # Suspicious session duration: either very short (reconnaissance) or erratic
    duration_type = np.random.choice(['short_bot', 'medium', 'prolonged_exfiltration'], size=n_suspicious, p=[0.60, 0.25, 0.15])
    suspicious_duration = []
    for dt in duration_type:
        if dt == 'short_bot':
            suspicious_duration.append(np.random.uniform(0.1, 3.5))
        elif dt == 'medium':
            suspicious_duration.append(np.random.uniform(3.5, 30.0))
        else:
            suspicious_duration.append(np.random.uniform(120.0, 480.0))
    suspicious_duration = np.array(suspicious_duration).round(1)
    
    # Suspicious device change: frequently 1 (~72%)
    suspicious_device_change = np.random.choice([0, 1], size=n_suspicious, p=[0.28, 0.72])
    
    # Suspicious location change: frequently 1 (~78%)
    suspicious_location_change = np.random.choice([0, 1], size=n_suspicious, p=[0.22, 0.78])
    
    # Suspicious IP risk score: elevated (0.45 to 0.98, VPNs, Tor, proxies)
    suspicious_ip_risk = np.clip(np.random.beta(a=6.0, b=2.2, size=n_suspicious), 0.35, 0.99).round(3)
    
    # Suspicious weekend indicator
    suspicious_weekend = np.random.choice([0, 1], size=n_suspicious, p=[0.55, 0.45])

    df_suspicious = pd.DataFrame({
        'login_hour': suspicious_hours,
        'failed_attempts': suspicious_failed,
        'session_duration': suspicious_duration,
        'device_change_indicator': suspicious_device_change,
        'location_change_indicator': suspicious_location_change,
        'ip_reputation_score': suspicious_ip_risk,
        'is_weekend': suspicious_weekend,
        'is_suspicious': 1
    })

    # Combine and shuffle
    df = pd.concat([df_routine, df_suspicious], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Add a unique Login_ID and human-readable timestamp for realism
    timestamps = []
    base_date = pd.Timestamp('2026-09-01 00:00:00')
    for idx, row in df.iterrows():
        random_day = np.random.randint(0, 25)
        minute = np.random.randint(0, 60)
        second = np.random.randint(0, 60)
        ts = base_date + pd.Timedelta(days=random_day, hours=int(row['login_hour']), minutes=minute, seconds=second)
        timestamps.append(ts.strftime('%Y-%m-%d %H:%M:%S'))
        
    df.insert(0, 'timestamp', timestamps)
    df.insert(0, 'login_id', [f'LOG-{i:06d}' for i in range(1, len(df) + 1)])
    
    return df

df_full = generate_login_data(n_samples=5000, suspicious_ratio=0.18)
out_path = r'C:\Users\mahal\.gemini\antigravity\scratch\suspicious_login_detection\data\login_activity_dataset.csv'
df_full.to_csv(out_path, index=False)
print(f'Generated {len(df_full)} records saved to {out_path}')
print(df_full['is_suspicious'].value_counts(normalize=True))

# Create sample test batch (50 rows without the label for upload testing)
batch_test = df_full.sample(n=50, random_state=123).copy()
batch_labels = batch_test.pop('is_suspicious')
batch_path = r'C:\Users\mahal\.gemini\antigravity\scratch\suspicious_login_detection\data\sample_test_batch.csv'
batch_test.to_csv(batch_path, index=False)
print(f'Generated 50-row batch test file saved to {batch_path}')
