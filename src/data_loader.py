"""
Cybersecurity Login Behavior Detection - Data Ingestion & Quality Analysis
"""
import os
import json
import numpy as np
import pandas as pd

REQUIRED_FEATURES = [
    'login_hour',
    'failed_attempts',
    'session_duration',
    'device_change_indicator',
    'location_change_indicator'
]

OPTIONAL_FEATURES = [
    'ip_reputation_score',
    'is_weekend'
]

ALL_FEATURES = REQUIRED_FEATURES + OPTIONAL_FEATURES
TARGET_COL = 'is_suspicious'

def load_data(filepath='data/login_activity_dataset.csv'):
    """Load login dataset from CSV with schema validation."""
    if not os.path.exists(filepath):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = os.path.join(base_dir, 'data', 'login_activity_dataset.csv')
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}")
        
    df = pd.read_csv(filepath)
    validate_schema(df)
    return df

def validate_schema(df):
    """Validate presence and types of mandatory features."""
    missing = [c for c in REQUIRED_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing mandatory cybersecurity features: {missing}")
    return True

def get_data_quality_report(df):
    """
    Perform deep data quality analysis:
    - Missing value counts
    - Duplicate detection
    - Outlier bounds via IQR
    - Class balance analysis
    """
    report = {
        'total_records': int(len(df)),
        'missing_values': {k: int(v) for k, v in df.isnull().sum().items()},
        'duplicate_records': int(df.duplicated(subset=[c for c in ALL_FEATURES if c in df.columns]).sum()),
        'total_features': int(len(df.columns)),
        'features_list': [c for c in df.columns if c not in ['login_id', 'timestamp', TARGET_COL]]
    }
    
    if TARGET_COL in df.columns:
        counts = df[TARGET_COL].value_counts().to_dict()
        proportions = df[TARGET_COL].value_counts(normalize=True).round(4).to_dict()
        report['class_distribution'] = {
            'routine_logins_0': int(counts.get(0, 0)),
            'suspicious_logins_1': int(counts.get(1, 0)),
            'routine_ratio': float(proportions.get(0, 0.0)),
            'suspicious_ratio': float(proportions.get(1, 0.0))
        }
        
    # Statistical outliers detection using Interquartile Range (IQR)
    num_cols = ['failed_attempts', 'session_duration', 'login_hour']
    outliers = {}
    for col in num_cols:
        if col in df.columns:
            q1 = float(df[col].quantile(0.25))
            q3 = float(df[col].quantile(0.75))
            iqr = q3 - q1
            lower = float(q1 - 1.5 * iqr)
            upper = float(q3 + 1.5 * iqr)
            outlier_cnt = int(((df[col] < lower) | (df[col] > upper)).sum())
            outliers[col] = {
                'q1': round(q1, 2),
                'q3': round(q3, 2),
                'iqr': round(iqr, 2),
                'lower_bound': round(lower, 2),
                'upper_bound': round(upper, 2),
                'outlier_count': outlier_cnt,
                'outlier_percentage': round((outlier_cnt / len(df)) * 100, 2)
            }
    report['outliers'] = outliers
    return report

if __name__ == '__main__':
    df = load_data()
    rep = get_data_quality_report(df)
    print("=== DATA QUALITY REPORT ===")
    print(f"Total Rows: {rep['total_records']}")
    print(f"Duplicates: {rep['duplicate_records']}")
    print(f"Missing Values: {rep['missing_values']}")
    print(f"Class Distribution: {rep['class_distribution']}")
    print("Outliers summary:", rep['outliers'])
