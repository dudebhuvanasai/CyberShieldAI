# CyberShield AI

## Project Overview
CyberShield AI is a beginner cybersecurity project that analyzes URLs
using simple rule-based checks and displays risk summaries in charts.

## Objectives
- Inspect URL structure and hostname.
- Check selected suspicious URL patterns.
- Assign an indicative risk score.
- Visualize analysis history.

## Technologies
- Python
- Pandas
- Matplotlib
- Google Colab

## How It Works
The program checks selected URL features, such as IP-address hosts,
URL length, account-related keywords, URL shorteners, and HTTPS usage.
It combines these signals into a Low, Medium, or High risk category.

## Run Instructions
1. Open the project notebook in Google Colab.
2. Run the code cells from top to bottom.
3. Analyze URLs using the provided function.
4. Run the dashboard cell to generate charts.

## Dataset
The current prototype uses illustrative test URLs and rule-based checks.
It does not yet use a validated labeled dataset or a trained ML model.
Add a real dataset link here if one is incorporated in a future version.

## Limitations
Risk labels are heuristic estimates, not proof that a website is safe
or malicious. The prototype has not been validated using a labeled
dataset.

## Author
Dude Bhuvana Sai
