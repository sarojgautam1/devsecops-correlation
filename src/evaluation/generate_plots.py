import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

PLOTS_DIR = "results/plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
sns.set_theme(style="whitegrid")

def plot_performance_comparison():
    data = {
        'Tool/Model': ['Semgrep Alone', 'SonarQube Alone', 'Heuristic Engine (P1)', 'Hybrid ML (5-Fold CV)', 'Hybrid ML (P1+P2 Filtered)'],
        'Precision': [67.52, 77.94, 100.0, 69.25, 83.10],
        'Recall': [82.26, 41.20, 21.46, 86.64, 46.57],
        'F1-Score': [74.16, 53.91, 35.34, 76.91, 59.69]
    }
    df = pd.DataFrame(data)
    df_melted = df.melt(id_vars='Tool/Model', var_name='Metric', value_name='Percentage')

    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df_melted, x='Tool/Model', y='Percentage', hue='Metric', palette=['#1f77b4', '#ff7f0e', '#2ca02c'])
    plt.title('DevSecOps Correlation Performance Comparison (%)', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Percentage (%) / F1 Score x100', fontsize=12)
    plt.xlabel('Tool / Priority Model', fontsize=12)
    plt.ylim(0, 115)

    for p in ax.patches:
        height = p.get_height()
        if height > 0:
            ax.annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                        ha='center', va='bottom', fontsize=9, xytext=(0, 3), textcoords='offset points')

    plt.xticks(rotation=15, ha='right')
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/01_performance_comparison.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/01_performance_comparison.png")


def plot_confusion_matrices():
    # True Positives, False Positives, False Negatives, True Negatives
    # Semgrep: TP=1127, FP=542, FN=243, TN=828
    semgrep_cm = np.array([[828, 542], [243, 1127]])
    # Sonar: TP=565, FP=160, FN=805, TN=1210
    sonar_cm = np.array([[1210, 160], [805, 565]])
    # ML (CV): TP=1187, FP=527, FN=183, TN=843
    ml_cm = np.array([[843, 527], [183, 1187]])

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    
    cms = [
        (semgrep_cm, "Semgrep Alone", axes[0]),
        (sonar_cm, "SonarQube Alone", axes[1]),
        (ml_cm, "Hybrid ML Model (5-Fold CV)", axes[2])
    ]

    for cm, title, ax in cms:
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False,
                    xticklabels=['Predicted FP', 'Predicted TP'],
                    yticklabels=['Actual FP', 'Actual TP'], annot_kws={"size": 11, "weight": "bold"})
        ax.set_title(title, fontsize=12, fontweight='bold')

    plt.suptitle('Confusion Matrix Comparison (True Positives vs False Positives)', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/02_confusion_matrices.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/02_confusion_matrices.png")


def plot_feature_importance():
    features = [
        ('Cross-Tool Agreement (num_tools)', 0.2301),
        ('Flagged by Semgrep', 0.1173),
        ('TF-IDF Keyword "use"', 0.0894),
        ('Flagged by SonarQube', 0.0855),
        ('TF-IDF Keyword "detected"', 0.0820),
        ('CWE Historical Precision', 0.0583),
        ('TF-IDF Keyword "instead"', 0.0493),
        ('TF-IDF Keyword "java"', 0.0358),
        ('CWE-330 Category', 0.0344),
        ('TF-IDF Keyword "going"', 0.0283)
    ]
    df_feat = pd.DataFrame(features, columns=['Feature', 'Importance']).sort_values('Importance', ascending=True)

    plt.figure(figsize=(10, 6))
    bars = plt.barh(df_feat['Feature'], df_feat['Importance'] * 100, color='#2b5c8f')
    plt.title('Top 10 Feature Importances in Hybrid ML Model (%)', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Importance Weight (%)', fontsize=12)

    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height()/2, f'{width:.1f}%', va='center', fontsize=10, fontweight='bold')

    plt.xlim(0, 27)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/03_feature_importance.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/03_feature_importance.png")


def plot_cwe_precision():
    cwe_df = pd.read_csv("results/cwe_precision_table.csv")
    cwe_df['precision_pct'] = cwe_df['precision'] * 100
    cwe_df = cwe_df.sort_values('precision_pct', ascending=False)

    plt.figure(figsize=(10, 6))
    colors = ['#2ca02c' if p >= 85 else '#ff7f0e' if p >= 65 else '#d62728' for p in cwe_df['precision_pct']]
    bars = plt.bar(cwe_df['cwe'].astype(str), cwe_df['precision_pct'], color=colors)

    plt.title('Scanner Precision by Vulnerability Category (CWE)', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Precision (%)', fontsize=12)
    plt.xlabel('CWE Category', fontsize=12)
    plt.axhline(85, color='green', linestyle='--', label='Tier A (≥85%)')
    plt.axhline(65, color='orange', linestyle='--', label='Tier B (≥65%)')
    plt.ylim(0, 115)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 2, f'{height:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/04_cwe_precision_breakdown.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/04_cwe_precision_breakdown.png")


def plot_priority_distribution():
    tiers = ['P1 - Critical Risk', 'P2 - High Risk', 'P3 - Medium Risk', 'P4 - Low / Suppressed']
    counts = [390, 403, 1046, 901]
    colors = ['#d62728', '#ff7f0e', '#1f77b4', '#7f7f7f']

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=tiers, autopct='%1.1f%%', startangle=140, colors=colors, explode=(0.05, 0.05, 0, 0), textprops={'fontsize': 11, 'weight': 'bold'})
    plt.title('ML Risk Triage Distribution (2,740 OWASP Benchmark Cases)', fontsize=13, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/05_ml_priority_distribution.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/05_ml_priority_distribution.png")


if __name__ == '__main__':
    plot_performance_comparison()
    plot_confusion_matrices()
    plot_feature_importance()
    plot_cwe_precision()
    plot_priority_distribution()
    print("All plots successfully generated!")
