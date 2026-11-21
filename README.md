# Cross-Tool Correlation and Learned Prioritization of SAST and SCA Findings in DevSecOps Pipelines

## Project Overview

This project presents a framework for correlating security findings from
multiple Static Application Security Testing (SAST) and Software
Composition Analysis (SCA) tools and prioritizing them using rule-based
techniques and machine learning.

The objective is to reduce security alert fatigue, identify overlapping
findings across tools, and improve vulnerability triage in DevSecOps
pipelines. The research uses the OWASP Benchmark v1.2.

## Tools and Technologies

  Tool / Technology        Purpose
  ------------------------ -----------------------------------------------------
  Semgrep                  Static Application Security Testing
  SonarQube                Static Application Security Testing
  OWASP Dependency-Check   Software Composition Analysis
  Python                   Data processing and machine-learning implementation
  Random Forest            Machine-learning-based prioritization
  Groq / OpenAI APIs       Experimental LLM-based validation
  GitHub Actions           Workflow automation

## Framework Workflow

1.  **Data Collection:** Collect findings from Semgrep, SonarQube and
    OWASP Dependency-Check.
2.  **Normalization:** Convert tool-specific findings into a common
    representation.
3.  **Filtering and Scoring:** Process findings and extract relevant
    attributes.
4.  **Cross-Tool Correlation:** Identify related findings using
    attributes such as CWE identifiers, file locations and line
    proximity.
5.  **Rule-Based Prioritization:** Assign findings to four priority
    levels (P1--P4).
6.  **Machine Learning:** Apply a Random Forest model to prioritize
    findings.
7.  **Validation:** Evaluate prioritization results against OWASP
    Benchmark ground-truth labels.
8.  **LLM-Based Validation:** Experiment with LLM-assisted verification
    of selected P3 findings.

Priority levels support human review ordering. A low-priority
classification is not proof that a finding is harmless and should not
automatically result in suppression.

## Repository Structure

``` text
devsecops-correlation/
├── .github/
│   └── workflows/
├── dashboard/
├── results/
│   ├── plots/
│   ├── correlated_findings.csv
│   ├── merged_findings.csv
│   ├── cwe_precision_table.csv
│   ├── depcheck_summary.csv
│   ├── feature_importance.csv
│   ├── manual_validation_sample.csv
│   ├── ml_evaluation_summary.csv
│   ├── ml_prioritized_findings.csv
│   ├── semgrep_filtered.csv
│   ├── semgrep_scored.csv
│   ├── sonar_filtered.csv
│   └── sonar_scored.csv
├── src/
├── .env.example
├── sonar-project.properties
├── sonar-project-juliet.properties
└── README.md
```

The `results/` directory also contains additional CSV files for
priority-tier validation, LLM validation and experimental comparisons.

## Research Results

The associated manuscript reports the following findings:

-   3,300 normalized and filtered SAST findings were reduced to 2,176
    correlated findings.
-   67.3% of true-positive findings were reported by only one scanner.
-   The leakage-controlled Random Forest model achieved a ROC-AUC of
    0.8406.
-   Restricting review to P1 and P2 achieved 86.70% precision at 46.08%
    recall.
-   LLM-based verification of selected P3 findings produced limited
    precision improvements, accompanied by reductions in F1 score.

The heuristic and machine-learning evaluations use different
populations. Their priority-tier metrics should not be interpreted as a
direct like-for-like comparison.

## Experimental Data

The `results/` directory contains processed research datasets and
evaluation outputs, including:

-   `merged_findings.csv` --- Merged security findings.
-   `correlated_findings.csv` --- Cross-tool correlation results.
-   `ml_prioritized_findings.csv` --- Machine-learning prioritization
    results.
-   `ml_evaluation_summary.csv` --- Model evaluation metrics.
-   `cwe_precision_table.csv` --- CWE-based precision information.
-   `feature_importance.csv` --- Machine-learning feature importance.
-   `manual_validation_sample.csv` --- Manually validated findings.
-   `depcheck_summary.csv` --- Dependency-Check results.
-   `p3_llm_validation_summary.csv` --- P3 LLM validation results.

These are processed or derived research artifacts. Their presence should
not be taken to mean that all original, native scanner reports are
included.

## Dataset

The study uses OWASP Benchmark v1.2 as its primary ground-truth dataset.

Official project: https://owasp.org/www-project-benchmark/

The quantitative ground-truth evaluation focuses on SAST findings.
Dependency-Check results are analysed descriptively and are not
evaluated against the OWASP Benchmark labels.

## Reproducibility

The repository provides source code, processed experimental datasets,
evaluation outputs and visualization artifacts.

To reproduce the experiments:

1.  Obtain the OWASP Benchmark v1.2 dataset.
2.  Configure Semgrep, SonarQube and OWASP Dependency-Check.
3.  Configure the required environment variables.
4.  Execute the relevant data collection and processing scripts in
    `src/`.
5.  Run the correlation and prioritization stages.
6.  Execute the evaluation scripts.
7.  Compare generated outputs with the corresponding files in
    `results/`.

Refer to the source scripts and configuration files for implementation
details. Exact execution commands and dependency versions should be
documented alongside the corresponding scripts before treating the
repository as a fully reproducible package.

## Methodological Notes and Limitations

-   The primary quantitative evaluation uses the OWASP Benchmark and
    does not establish generalization to all real-world software
    projects.
-   The heuristic CWE precision calculation uses the full labelled
    dataset and is therefore partly in-sample.
-   The Random Forest evaluation uses fold-safe CWE-derived features.
-   The heuristic and ML approaches are evaluated on different
    populations.
-   SCA findings are not evaluated against labelled OWASP Benchmark
    ground truth.
-   LLM validation is restricted to the tested models, prompts and
    selected findings.

Priority levels are intended to support vulnerability triage and should
not be interpreted as proof that lower-priority findings are harmless.

## Data Availability

The processed datasets and derived research artifacts generated and
analysed during this study are available in this public repository:

https://github.com/sarojgautam1/devsecops-correlation

The OWASP Benchmark v1.2 dataset is available through the official OWASP
project.

## Research Publication

This repository supports the manuscript:

**Cross-Tool Correlation and Learned Prioritization of SAST and SCA
Findings in DevSecOps Pipelines: An Empirical Evaluation on the OWASP
Benchmark.**

The repository is intended to support transparency, inspection of
experimental outputs and reproducibility of the research.

------------------------------------------------------------------------

**Note:** The reported experimental results should be interpreted within
the methodology and limitations described in the associated manuscript.
