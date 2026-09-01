# 🛡️ AI Cyber Defense Guardian

AI Cyber Defense Guardian is an AI-powered cybersecurity threat detection and risk analysis system. It combines rule-based security analysis with machine-learning anomaly detection to identify suspicious authentication activity and provide understandable security recommendations.

## 🌐 Live Demo

🚀 **[Open AI Cyber Defense Guardian Live Dashboard](https://duo-stretch-wool-remind.trycloudflare.com)**

> The live demo is provided through a temporary Cloudflare Quick Tunnel for development and demonstration purposes. The link is available only while the local Flask server and Cloudflare Tunnel are running.
 
## 🚀 Project Overview

The system simulates cybersecurity login events and analyzes them to determine the potential security risk.

The application can detect and analyze:

- Normal login activity
- Failed login attempts
- Login from a new IP address
- Multiple failed login attempts
- Suspicious login activity
- AI-detected anomalous behavior

After analyzing an event, the system calculates a final risk score and classifies the event as:

- 🟢 LOW
- 🟡 MEDIUM
- 🟠 HIGH
- 🔴 CRITICAL

## ✨ Features

### 🔍 Security Event Simulation

The system generates simulated authentication events containing information such as:

- Username
- IP address
- Timestamp
- Failed login attempts
- New IP address status
- Unusual login time

### 🧠 AI Anomaly Detection

A machine-learning anomaly detection model analyzes authentication behavior and identifies potentially unusual activity.

### 🛡️ Rule-Based Threat Detection

Security rules evaluate events using factors such as:

- Number of failed login attempts
- New IP address
- Unusual login time

### 📊 Risk Scoring

The system combines rule-based analysis and AI anomaly detection to calculate a final security risk score.

| Risk Score | Severity |
|------------|----------|
| 0–39 | 🟢 LOW |
| 40–59 | 🟡 MEDIUM |
| 60–79 | 🟠 HIGH |
| 80–100 | 🔴 CRITICAL |

### 💡 Explainable AI

The system provides an explanation for detected threats, including:

- Threat type
- Reasons for detection
- Confidence level
- Defensive recommendations

### 📈 Security Dashboard

The web dashboard displays:

- Total security events
- Critical threats
- High-risk threats
- Current risk score
- Live threat monitoring
- Security risk analytics
- Threat distribution
- AI analysis
- Defensive recommendations
- Incident timeline

## 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │   Security Event    │
                    │     Simulator       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Rule-Based Threat  │
                    │      Detector       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   AI Anomaly        │
                    │     Detector        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Risk Engine      │
                    │  Final Risk Score   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Explainable AI    │
                    │  Threat Explanation │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Security Dashboard │
                    └─────────────────────┘
```

## 📁 Project Structure

```text
AI-Cyber-Defense-Guardian/
│
├── Backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── simulator.py
│   │
│   ├── ai/
│   │   └── anomaly_detector.py
│   │
│   └── detection/
│       ├── threat_detector.py
│       ├── risk_engine.py
│       └── explainer.py
│
├── ml/
├── reports/
│
├── index.html
├── app.js
├── style.css
├── .gitignore
└── README.md
```

## 🛠️ Technologies Used

### Frontend

- HTML5
- CSS3
- JavaScript
- Chart.js

### Backend

- Python
- Flask
- Flask-CORS
- Gunicorn

### Machine Learning

- Scikit-learn
- NumPy
- Pandas
- Isolation Forest / Anomaly Detection

### Version Control and Deployment

- Git
- GitHub
- SnapDeploy

## 🔄 How the System Works

### Step 1 — Generate Security Event

The security simulator generates an authentication event.

Example:

```json
{
  "event_type": "multiple_failed_logins",
  "username": "alice",
  "failed_attempts": 8,
  "new_ip": 1
}
```

### Step 2 — Rule-Based Analysis

The event is analyzed using predefined cybersecurity rules.

The rules evaluate factors such as:

- Failed login attempts
- New IP addresses
- Unusual login times

### Step 3 — AI Analysis

The machine-learning model analyzes the event and determines whether the behavior appears anomalous.

### Step 4 — Final Risk Calculation

The rule-based risk score and AI anomaly result are combined to produce the final risk score and severity.

### Step 5 — Explainable AI

The system generates an explanation describing why the activity may be suspicious and provides recommended defensive actions.

### Step 6 — Dashboard

The results are displayed on the cybersecurity dashboard using:

- Risk indicators
- Threat cards
- Charts
- AI analysis
- Defensive recommendations
- Incident timeline

## 🌐 API Endpoints

### Health Check

```text
GET /health
```

Example response:

```json
{
  "service": "AI Cyber Defense Guardian",
  "status": "healthy"
}
```

### Security Analysis

```text
GET /api/analyze
```

This endpoint generates a security event and performs:

1. Rule-based threat analysis
2. AI anomaly detection
3. Final risk calculation
4. Threat explanation
5. Defensive recommendations

Example response structure:

```json
{
  "event": {},
  "rule_analysis": {},
  "ai_analysis": {},
  "final_risk": {},
  "explanation": {}
}
```

## 💻 Running the Project Locally

### 1. Clone the Repository

```bash
git clone https://github.com/adithyaadithya2662-dotcom/AI-Cyber-Defense-Guardian.git
```

### 2. Enter the Project Directory

```bash
cd AI-Cyber-Defense-Guardian
```

### 3. Create a Virtual Environment

On Windows:

```powershell
python -m venv venv
```

### 4. Activate the Virtual Environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```powershell
pip install -r Backend\requirements.txt
```

### 6. Start the Flask Backend

```powershell
python Backend\app.py
```

The application will run on:

```text
http://localhost:5000
```

Open the address in a browser to access the dashboard.

## 📊 Example Threat Detection

A suspicious authentication event may contain:

```text
Failed login attempts: 8
New IP address: Yes
AI anomaly: Detected
```

The system may classify the event as:

```text
Risk Score: 95
Severity: CRITICAL
```

Possible defensive recommendations include:

```text
• Investigate the source IP address
• Enable or verify multi-factor authentication
• Review recent account activity
• Consider temporarily blocking the suspicious source
```

## 🎯 Project Objectives

The main objectives of AI Cyber Defense Guardian are:

1. Detect suspicious authentication behavior.
2. Combine traditional cybersecurity rules with machine learning.
3. Calculate understandable cybersecurity risk scores.
4. Explain why potentially dangerous activity was detected.
5. Provide practical defensive recommendations.
6. Present security information through an easy-to-understand dashboard.
7. Demonstrate the use of AI techniques in cybersecurity monitoring.

## 🔮 Future Improvements

Possible future improvements include:

- Real-time security log ingestion
- Real authentication log integration
- Email security alerts
- SMS notifications
- Advanced machine-learning models
- User behavior analytics
- IP reputation checking
- Geo-location analysis
- Automated incident response
- Security report generation
- Database integration
- Authentication and role-based access control
- Historical security event storage

## ⚠️ Disclaimer

This project is intended for educational, research, and demonstration purposes.

The security events used by the current system are simulated and should not be treated as real-world security incidents.

## 👨‍💻 Author

**Adithya**

AI Cyber Defense Guardian

A cybersecurity project combining:

**Artificial Intelligence + Machine Learning + Threat Detection + Risk Analysis + Explainable AI**

## ⭐ Repository

GitHub Repository:

https://github.com/adithyaadithya2662-dotcom/AI-Cyber-Defense-Guardian.git
