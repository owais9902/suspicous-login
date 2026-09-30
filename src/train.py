"""
Cybersecurity Login Behavior Detection - Foundational Model Training & Cross-Validation
Trains Logistic Regression, KNN, Decision Tree, and Random Forest baseline.
Saves models and serializes metrics summary.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, log_loss
)

from preprocess import prepare_data, create_preprocessor

def train_and_evaluate():
    os.makedirs('models', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # 1. Prepare data with zero leakage
    X_train, X_test, y_train, y_test, preprocessor = prepare_data()
    
    # 2. Define Foundational Models + Ensemble Comparison
    models = {
        'Logistic Regression': LogisticRegression(
            C=1.0, 
             
            class_weight='balanced', 
            solver='lbfgs', 
            max_iter=1000, 
            random_state=42
        ),
        'K-Nearest Neighbors': KNeighborsClassifier(
            n_neighbors=7, 
            weights='distance', 
            metric='euclidean'
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=5, 
            min_samples_split=10, 
            min_samples_leaf=4, 
            class_weight='balanced', 
            random_state=42
        ),
        'Random Forest (Baseline)': RandomForestClassifier(
            n_estimators=100, 
            max_depth=7, 
            class_weight='balanced', 
            random_state=42
        )
    }
    
    results = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    print("\n" + "="*70)
    print("CYBERSECURITY FOUNDATIONAL MODEL TRAINING & BENCHMARKING")
    print("="*70)
    
    for name, clf in models.items():
        # Build end-to-end pipeline
        pipeline = Pipeline(steps=[
            ('preprocessor', create_preprocessor()),
            ('classifier', clf)
        ])
        
        # 5-Fold Stratified Cross Validation on Train Set
        cv_auc = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring='roc_auc').mean()
        cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring='f1').mean()
        
        # Train on full X_train
        pipeline.fit(X_train, y_train)
        
        # Predict on Test Set
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else y_pred
        
        # Calculate metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_prob)
        loss = log_loss(y_test, y_prob)
        
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        specificity = tn / (tn + fp)
        
        results[name] = {
            'cv_roc_auc': round(float(cv_auc), 4),
            'cv_f1_score': round(float(cv_f1), 4),
            'test_accuracy': round(float(acc), 4),
            'test_precision': round(float(prec), 4),
            'test_recall': round(float(rec), 4),
            'test_f1_score': round(float(f1), 4),
            'test_roc_auc': round(float(auc), 4),
            'test_specificity': round(float(specificity), 4),
            'test_log_loss': round(float(loss), 4),
            'confusion_matrix': {
                'true_negatives_routine': int(tn),
                'false_positives_friction': int(fp),
                'false_negatives_breach': int(fn),
                'true_positives_detected': int(tp)
            }
        }
        
        # Save individual model
        clean_name = name.lower().split()[0].replace('(', '')
        model_filename = f"models/{clean_name}.pkl"
        joblib.dump(pipeline, model_filename)
        
        print(f"\nModel: {name}")
        print(f"  CV ROC-AUC: {cv_auc:.4f} | CV F1: {cv_f1:.4f}")
        print(f"  Test Accuracy: {acc*100:.2f}% | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {auc:.4f}")
        print(f"  Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn} (Breach Risk)")
        
    # Model Selection: We prioritize Foundational models.
    # Between Decision Tree and Logistic Regression, select highest test F1-score & Recall
    foundational_models = ['Logistic Regression', 'Decision Tree', 'K-Nearest Neighbors']
    best_foundational_name = max(foundational_models, key=lambda m: (results[m]['test_f1_score'], results[m]['test_recall']))
    
    print("\n" + "="*70)
    print(f"SELECTED PRODUCTION MODEL: {best_foundational_name}")
    print(f"Justification: Optimal trade-off between Recall (catching attacks) and Precision (minimizing user friction).")
    print("="*70)
    
    # Save the selected model as best_model.pkl
    best_clean = best_foundational_name.lower().split()[0]
    best_pipe = joblib.load(f"models/{best_clean}.pkl")
    joblib.dump(best_pipe, 'models/best_model.pkl')
    
    # Save test set for evaluation script
    test_df = X_test.copy()
    test_df['is_suspicious'] = y_test.values
    test_df.to_csv('data/evaluated_test_set.csv', index=False)
    
    # Save metrics JSON
    with open('reports/metrics_summary.json', 'w') as f:
        json.dump(results, f, indent=2)
        
    print("\nAll models trained and saved to models/")
    print("Metrics summary saved to reports/metrics_summary.json")
    return results

if __name__ == '__main__':
    train_and_evaluate()
