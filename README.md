# 🛡️ Advanced AI-Powered SOC Analyst Tool

An AI-powered Security Operations Center (SOC) tool built with Python and Streamlit to analyze security logs, identify suspicious activity, support threat intelligence checks, and generate investigation reports.

## 📌 Project Overview

This project assists security analysts with the initial investigation of security logs. It uses the Groq API to analyze log events and provide structured findings, including classification, severity, confidence, possible MITRE ATT&CK mapping, and recommended actions.

**Note:** AI-generated findings are advisory and must be verified by a human analyst.

## ✨ Features

- **AI Log Analysis:** Analyze individual security logs using the Groq API.
- **Security Classification:** Classify events as Normal, Suspicious, or Malicious.
- **Severity Assessment:** Identify Low, Medium, High, and Critical severity levels.
- **MITRE ATT&CK Mapping:** Suggest relevant tactics and techniques.
- **Data Masking:** Mask common credentials, email addresses, usernames, and IPv4 addresses before AI analysis.
- **Batch Analysis:** Analyze TXT and CSV files, with a configurable limit of up to 50 events per batch.
- **Investigation History:** Store investigation results in an SQLite database.
- **False-Positive Feedback:** Record false-positive feedback and its reason.
- **Threat Intelligence:** Check eligible public IPv4 addresses using AbuseIPDB.
- **Email Alerts:** Optionally send alerts for High and Critical findings.
- **Evaluation Metrics:** Calculate accuracy, precision, recall, F1 score, and confusion-matrix counts when ground-truth labels are available.
- **Dashboard:** View classification and severity distributions.
- **Report Generation:** Download Markdown, HTML, and PDF investigation reports.
- **CSV Export:** Export batch analysis results and investigation history.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Web interface |
| Groq API | AI-based log analysis |
| SQLite | Investigation history database |
| Pandas | Data processing and metrics |
| ReportLab | PDF report generation |
| Markdown | HTML report formatting |
| Requests | AbuseIPDB API requests |
| Python Standard Library | CSV, JSON, regular expressions, IP validation, and email alerts |

## ⚙️ Requirements

- Python 3.10 or a compatible version supported by your installed packages
- Internet connection
- Groq API key
- Optional AbuseIPDB API key
- Optional email alert configuration

## 🚀 Installation

### 1. Download or clone the project

Place `SOC_app.py` in your project folder.

### 2. Create a virtual environment (recommended)

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install streamlit groq pandas requests reportlab Markdown
```

### 4. Configure environment variables

Set your Groq API key in PowerShell:

```powershell
$env:GROQ_API_KEY="your_groq_api_key"
```

Optional model configuration:

```powershell
$env:GROQ_MODEL="openai/gpt-oss-120b"
```

Set login credentials:

```powershell
$env:SOC_ADMIN_USERNAME="socadmin"
$env:SOC_ADMIN_PASSWORD="your_admin_password"
$env:SOC_JUNIOR_USERNAME="junior"
$env:SOC_JUNIOR_PASSWORD="your_junior_password"
```

Optional AbuseIPDB configuration:

```powershell
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

Optional email alert configuration:

```powershell
$env:ALERT_EMAIL_FROM="your_sender_email"
$env:ALERT_EMAIL_PASSWORD="your_email_app_password"
$env:ALERT_EMAIL_TO="your_recipient_email"
```

**Security warning:** Replace all example values with your own credentials. Never upload API keys, passwords, or other secrets to GitHub.

These PowerShell environment variables apply to the current terminal session. Configure them again in a new terminal, or use an appropriate secrets-management method.

## ▶️ Run the Application

From the project directory, run:

```bash
py -m streamlit run SOC_app.py
```

Open the local URL displayed in the terminal, usually:

`http://localhost:8501`

Log in with the Admin or Junior Analyst credentials you configured.

## 📂 Supported Input Files

### TXT Files

Use one security event per line.

Example:

```text
LOGIN FAILED - User: admin - IP: 185.73.21.44
LOGIN FAILED - User: admin - IP: 185.73.21.44
LOGIN SUCCESS - User: admin - IP: 185.73.21.44
```

### CSV Files

Include a column containing the log event. A ground-truth label column is optional.

Example:

```csv
log,true_label
"LOGIN FAILED - User: admin - IP: 185.73.21.44",Suspicious
"Scheduled backup completed successfully",Normal
```

Supported log column names include `log`, `log_line`, `event`, `message`, and `text`.

Supported label column names include `true_label`, `label`, `actual`, `ground_truth`, and `target`.

Use synthetic logs for testing and ensure labels accurately represent the test data.

## 📊 Evaluation Metrics

When valid ground-truth labels are provided, the application calculates:

- **Accuracy:** Overall proportion of correct predictions.
- **Precision:** Proportion of predicted positive cases that are actually positive.
- **Recall:** Proportion of actual positive cases detected.
- **F1 Score:** Harmonic mean of precision and recall.
- **TP, TN, FP, FN:** True positives, true negatives, false positives, and false negatives.

Metric results depend on the quality and representativeness of the labelled test dataset.

## 🗄️ Database

The application automatically creates `soc_history.db` in its working directory.

The database stores investigation records, including timestamps, log text, classifications, severity, confidence, MITRE fields, indicators, recommendations, and false-positive feedback.

Protect the database because it may contain sensitive log information.

## 📄 Reports and Exports

The application provides:

- Markdown investigation report
- Styled HTML investigation report
- PDF investigation report (Admin role)
- Batch analysis CSV
- Investigation history CSV (Admin role)

Check each downloaded report before submitting it.

## 🔐 Security and Privacy Notes

- Masking is pattern-based and does not guarantee removal of every sensitive value.
- Logs submitted for AI analysis are sent to the configured external Groq service after masking.
- Only eligible public IPv4 addresses are checked through AbuseIPDB.
- Email alerts require correctly configured credentials and network access.
- The current login implementation is intended for an educational prototype, not production deployment.
- AI results may be incorrect and should not independently trigger enforcement actions.
- Use synthetic or authorized test data during demonstrations.

## ⚠️ Limitations

- AI results require human verification.
- API access depends on connectivity, service availability, model support, and account limits.
- Batch processing is limited to 50 events per run.
- False-positive feedback is stored but does not automatically retrain the model.
- The application does not provide continuous monitoring or a complete incident-response platform.

## 🔮 Future Improvements

- Add stronger authentication and secure password storage.
- Improve masking and sensitive-data detection.
- Support more log formats and larger batches.
- Add log correlation and configurable detection rules.
- Add automated unit tests and integration tests.
- Improve audit logging, database backup, and retention controls.
- Evaluate performance using a larger labelled dataset.

## 📚 References

- Python: https://docs.python.org/3/
- Streamlit: https://docs.streamlit.io/
- Groq API: https://console.groq.com/docs
- Pandas: https://pandas.pydata.org/docs/
- ReportLab: https://docs.reportlab.com/
- AbuseIPDB API: https://docs.abuseipdb.com/
- MITRE ATT&CK: https://attack.mitre.org/

## 👨‍🎓 Project Information

**Project:** Advanced AI-Powered SOC Analyst Tool  
**Category:** Cybersecurity / Security Operations / AI-Assisted Log Analysis  
**Purpose:** Educational and academic project

---

*AI-generated security findings are advisory. Human validation is required before incident-response or enforcement decisions.*
