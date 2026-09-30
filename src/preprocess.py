"""
Cybersecurity Login Behavior Detection - Preprocessing Pipeline
Ensures zero data leakage between training and evaluation splits.
"""
import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer

# Primary 5 features requested in capstone guidelines
CORE_FEATURES = [
    'login_hour',
    'failed_attempts',
    'session_duration',
    'device_change_indicator',
    'location_change_indicator'
]

# Supplementary risk features (standard in RBA enterprise IAM logs)
AUX_FEATURES = [
    'ip_reputation_score',
    'is_weekend'
]

ALL_MODEL_FEATURES = CORE_FEATURES + AUX_FEATURES
TARGET = 'is_suspicious'

NUMERICAL_COLS = ['login_hour', 'failed_attempts', 'session_duration', 'ip_reputation_score']
BINARY_COLS = ['device_change_indicator', 'location_change_indicator', 'is_weekend']

def create_preprocessor():
    """Build a ColumnTransformer that scales continuous features and passes binary indicators."""
    transformer = ColumnTransformer(
        transformers=[
            ('scaler', StandardScaler(), NUMERICAL_COLS),
            ('binary', 'passthrough', BINARY_COLS)
        ],
        remainder='drop'
    )
    return transformer

def prepare_data(data_path='data/login_activity_dataset.csv', test_size=0.20, random_state=42):
    """
    Split dataset into train and test sets with stratification to preserve class balance.
    Fits preprocessor strictly on X_train to prevent any data leakage.
    """
    df = pd.read_csv(data_path)
    
    # Feature selection
    X = df[ALL_MODEL_FEATURES].copy()
    y = df[TARGET].copy()
    
    # Stratified Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    preprocessor = create_preprocessor()
    preprocessor.fit(X_train)
    
    # Save feature metadata for Streamlit input validation & inference
    os.makedirs('models', exist_ok=True)
    metadata = {
        'core_features': CORE_FEATURES,
        'aux_features': AUX_FEATURES,
        'all_features': ALL_MODEL_FEATURES,
        'numerical_features': NUMERICAL_COLS,
        'binary_features': BINARY_COLS,
        'target': TARGET,
        'train_samples': int(len(X_train)),
        'test_samples': int(len(X_test)),
        'class_distribution_train': {
            'routine': int((y_train == 0).sum()),
            'suspicious': int((y_train == 1).sum())
        },
        'feature_ranges': {
            'login_hour': {'min': 0, 'max': 23, 'default': 14},
            'failed_attempts': {'min': 0, 'max': 15, 'default': 0},
            'session_duration': {'min': 0.1, 'max': 480.0, 'default': 30.0},
            'device_change_indicator': {'options': [0, 1], 'default': 0},
            'location_change_indicator': {'options': [0, 1], 'default': 0},
            'ip_reputation_score': {'min': 0.0, 'max': 1.0, 'default': 0.05},
            'is_weekend': {'options': [0, 1], 'default': 0}
        }
    }
    
    with open('models/feature_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
        
    return X_train, X_test, y_train, y_test, preprocessor

if __name__ == '__main__':
    X_train, X_test, y_train, y_test, preprocessor = prepare_data()
    print("Preprocessing completed successfully.")
    print(f"X_train shape: {X_train.shape}, X_test shape: {X_test.shape}")
    print(f"y_train class balance: Routine={int((y_train==0).sum())}, Suspicious={int((y_train==1).sum())}")
    print(f"y_test class balance: Routine={int((y_test==0).sum())}, Suspicious={int((y_test==1).sum())}")
