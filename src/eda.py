"""
Cybersecurity Login Behavior Detection - Exploratory Data Analysis (EDA)
Generates publication-quality figures and statistical summaries.
"""
import os
import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

# Set aesthetic style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['figure.autolayout'] = True

def run_eda(data_path='data/login_activity_dataset.csv', output_dir='reports/figures'):
    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_csv(data_path)
    
    # 1. Class Balance Visualization
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    counts = df['is_suspicious'].value_counts()
    colors = ['#2b5c8f', '#d9534f']
    labels = ['Routine Access (0)', 'Suspicious Access (1)']
    
    sns.barplot(x=labels, y=counts.values, ax=axes[0], palette=colors)
    axes[0].set_title('Login Class Distribution (Counts)', fontsize=13, fontweight='bold')
    axes[0].set_ylabel('Number of Sessions')
    for i, v in enumerate(counts.values):
        axes[0].text(i, v + 50, f'{v} ({v/len(df)*100:.1f}%)', ha='center', fontweight='bold')
        
    axes[1].pie(counts.values, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140, explode=(0, 0.08))
    axes[1].set_title('Class Imbalance Proportion', fontsize=13, fontweight='bold')
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, 'class_balance.png'), dpi=300)
    plt.close()
    
    # 2. Failed Login Attempts by Class
    plt.figure(figsize=(9, 5))
    sns.histplot(data=df, x='failed_attempts', hue='is_suspicious', bins=16, multiple='dodge', shrink=0.8, palette=colors)
    plt.title('Failed Password Attempts: Routine vs. Suspicious', fontsize=13, fontweight='bold')
    plt.xlabel('Failed Password Attempts Prior to Login')
    plt.ylabel('Frequency')
    plt.legend(title='Classification', labels=['Suspicious', 'Routine'])
    plt.savefig(os.path.join(output_dir, 'failed_attempts_dist.png'), dpi=300)
    plt.close()

    # 3. Login Hour Temporal Analysis
    plt.figure(figsize=(10, 5))
    sns.kdeplot(data=df[df['is_suspicious'] == 0]['login_hour'], label='Routine Access', fill=True, color='#2b5c8f', alpha=0.4, bw_adjust=0.8)
    sns.kdeplot(data=df[df['is_suspicious'] == 1]['login_hour'], label='Suspicious Access', fill=True, color='#d9534f', alpha=0.4, bw_adjust=0.8)
    plt.title('Temporal Density: Hour of Day Login Activity', fontsize=13, fontweight='bold')
    plt.xlabel('Hour of Day (0 to 23 UTC)')
    plt.ylabel('Probability Density')
    plt.xticks(range(0, 24, 2))
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'login_hour_density.png'), dpi=300)
    plt.close()

    # 4. Session Duration Distribution (Log Scale Box Plot)
    plt.figure(figsize=(9, 5))
    sns.boxplot(data=df, x='is_suspicious', y='session_duration', palette=colors)
    plt.yscale('log')
    plt.xticks([0, 1], ['Routine Access (0)', 'Suspicious Access (1)'])
    plt.title('Session Duration Distribution (Log Scale)', fontsize=13, fontweight='bold')
    plt.xlabel('Authentication Category')
    plt.ylabel('Session Duration (Minutes, Log Scale)')
    plt.savefig(os.path.join(output_dir, 'session_duration_box.png'), dpi=300)
    plt.close()

    # 5. Device & Location Change Threat Impact
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    
    device_risk = df.groupby('device_change_indicator')['is_suspicious'].mean() * 100
    sns.barplot(x=['Same Device (0)', 'New Device (1)'], y=device_risk.values, ax=axes[0], palette=['#5bc0de', '#f0ad4e'])
    axes[0].set_title('Suspicious Rate by Device Change', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Suspicious Probability (%)')
    for i, v in enumerate(device_risk.values):
        axes[0].text(i, v + 1, f'{v:.1f}%', ha='center', fontweight='bold')

    loc_risk = df.groupby('location_change_indicator')['is_suspicious'].mean() * 100
    sns.barplot(x=['Same Location (0)', 'New Location (1)'], y=loc_risk.values, ax=axes[1], palette=['#5bc0de', '#d9534f'])
    axes[1].set_title('Suspicious Rate by Location Change', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('Suspicious Probability (%)')
    for i, v in enumerate(loc_risk.values):
        axes[1].text(i, v + 1, f'{v:.1f}%', ha='center', fontweight='bold')

    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, 'device_location_risk.png'), dpi=300)
    plt.close()

    # 6. Correlation Heatmap
    plt.figure(figsize=(9, 7))
    num_cols = [c for c in df.columns if c not in ['login_id', 'timestamp']]
    corr = df[num_cols].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, annot=True, fmt='.2f', cmap='coolwarm', vmin=-1, vmax=1, mask=mask, cbar_kws={'label': 'Pearson Correlation'})
    plt.title('Cybersecurity Feature Correlation Matrix', fontsize=13, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'correlation_heatmap.png'), dpi=300)
    plt.close()

    # Export statistical summary JSON
    eda_summary = {
        'total_samples': len(df),
        'correlations_with_target': corr['is_suspicious'].drop('is_suspicious').round(4).to_dict(),
        'mean_failed_attempts': {
            'routine': float(round(df[df['is_suspicious'] == 0]['failed_attempts'].mean(), 2)),
            'suspicious': float(round(df[df['is_suspicious'] == 1]['failed_attempts'].mean(), 2))
        },
        'median_session_duration': {
            'routine': float(round(df[df['is_suspicious'] == 0]['session_duration'].median(), 2)),
            'suspicious': float(round(df[df['is_suspicious'] == 1]['session_duration'].median(), 2))
        }
    }
    
    with open('reports/eda_summary.json', 'w') as f:
        json.dump(eda_summary, f, indent=2)

    print('EDA completed successfully. Figures generated in:', output_dir)
    print('Key correlations with is_suspicious:')
    for k, v in eda_summary['correlations_with_target'].items():
        print(f"  {k}: {v}")

if __name__ == '__main__':
    run_eda()
