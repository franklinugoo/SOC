# SOC Alert Triage Web App

A beginner-friendly Streamlit web app for triaging CSV alert exports from Microsoft Defender or Microsoft Sentinel.

This project is designed for learning, portfolio demonstrations, and safe public demos with sample data.

## What The App Does

The app lets a SOC analyst:

- Upload a CSV alert export.
- Preview the uploaded file before triage.
- Fill missing expected columns with blank values.
- Classify each alert as `Low`, `Medium`, `High`, or `Critical`.
- View a dashboard with Low, Medium, High, and Critical counts.
- Review the triaged alerts in a table.
- Download the final result as `triaged_alerts.csv`.

Uploaded files are processed in memory by Streamlit and pandas. The app does not permanently save uploaded CSV files.

## Project Files

- `app.py`: Streamlit browser interface.
- `triage_logic.py`: Alert classification and incident summary functions.
- `sample_alerts.csv`: Safe sample alerts for testing and demonstrations.
- `requirements.txt`: Python dependencies.
- `.gitignore`: Prevents local environments, logs, and real alert exports from being committed.

## Privacy Warning

Privacy Notice: This tool is for learning and demonstration purposes. Do not upload confidential, sensitive, client, government, or production security data unless you are authorised to do so.

If you deploy this app publicly, uploaded files may be processed by the hosting environment. Use sample or synthetic data for public demonstrations.

## Limitations

This tool uses basic rule-based logic. It does not replace a SIEM, SOC analyst, incident responder, or formal investigation process.

The classifications are based on simple severity normalization and keyword matching. Real investigations should include broader context such as identity logs, endpoint telemetry, network activity, asset criticality, threat intelligence, and business impact.

## Install Dependencies

From inside the project folder:

```bash
pip install -r requirements.txt
```

Optional virtual environment setup:

```bash
python -m venv .venv
```

On Windows PowerShell:

```bash
.\.venv\Scripts\Activate.ps1
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

## Run Locally

Start the app with:

```bash
streamlit run app.py
```

Streamlit will open the app in your browser. If it does not open automatically, copy the local URL from the terminal into your browser.

## Sample CSV Instructions

Use `sample_alerts.csv` to test the app safely.

1. Run the app locally.
2. Upload `sample_alerts.csv`.
3. Review the preview table.
4. Click `Triage alerts`.
5. Review the dashboard and triaged alert table.
6. Click `Download triaged_alerts.csv`.

The sample file includes Low, Medium, High, and Critical examples.

## Output Columns

The app keeps the original CSV columns and adds:

- `FinalClassification`: The final risk level assigned by the tool.
- `ClassificationReason`: Why the alert received that classification.
- `WhatHappened`: A short explanation of the alert source, title, time, and status.
- `AffectedEntity`: The clearest impacted user, device, IP address, URL, or process.
- `WhyItMatters`: A short SOC-focused explanation of the risk.
- `RecommendedNextAction`: A simple next step for the analyst.
- `IncidentSummary`: A combined summary for notes or escalation.

## Classification Logic

The app starts with the source `Severity` value if one is available. It then checks the alert title and description for SOC keywords. The final classification uses the highest risk level found.

Critical keywords:

- `ransomware`
- `data exfiltration`
- `command and control`
- `privilege escalation`
- `lateral movement`

High keywords:

- `malware`
- `credential theft`
- `impossible travel`
- `brute force`
- `suspicious login`

Medium keywords:

- `phishing`
- `suspicious URL`
- `external IP`
- `suspicious process`
- `blocked sign-in`

If there is no useful source severity and no suspicious keyword, the alert is classified as `Low`.

## Deploy To Streamlit Community Cloud

1. Create a GitHub repository for this project.
2. Commit and push these files:
   - `app.py`
   - `triage_logic.py`
   - `sample_alerts.csv`
   - `requirements.txt`
   - `README.md`
   - `.gitignore`
3. Go to Streamlit Community Cloud.
4. Select `New app`.
5. Choose your GitHub repository and branch.
6. Set the main file path to:

```text
app.py
```

7. Deploy the app.
8. Test the deployed app using `sample_alerts.csv`.

Before sharing the public URL, confirm your privacy and data handling requirements are understood.
