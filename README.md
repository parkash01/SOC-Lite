# 🛡️ SOC-Lite

A lightweight Python-based Security Operations Center (SOC) log analyzer.

SOC-Lite analyzes authentication logs, detects suspicious login activity,
identifies potentially malicious IP addresses, assigns severity levels,
and generates a CSV security report.

## 🚀 Features

- 🔍 Failed login detection
- 🌐 Suspicious IP detection
- 🚨 Severity classification
- 👤 Targeted username analysis
- 📊 CSV security report
- 🐍 Built with Python
- 📁 Sample authentication logs

## ⚙️ Severity Levels

| Failed Attempts | Severity |
|---|---|
| 1–2 | LOW |
| 3–4 | MEDIUM |
| 5–9 | HIGH |
| 10+ | CRITICAL |

## 📂 Project Structure

```text
SOC-Lite/
├── analyzer.py
├── sample_logs/
│   └── auth.log
├── reports/
│   └── security_report.csv
├── README.md
└── .gitignore