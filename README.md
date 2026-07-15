# MAPIS - Multilayer Adaptive Phishing Intelligence System

MAPIS is a full-stack phishing detection platform that analyzes URLs and emails, shows live dashboard analytics, and warns users through a Chrome Extension when a suspicious or phishing website is opened.

The project combines:

- React cybersecurity dashboard
- Flask ML and analysis API
- Random Forest phishing model
- Chrome Extension Manifest V3
- Real-time scan history, alerts, and risk scoring
- Admin login and blacklist management

## Current Status

The system is working with:

- URL scanning
- Email scanning
- Dashboard analytics
- Real-time alerts
- Chrome Extension background scanning
- Automatic suspicious-site warning popup
- Admin login
- Blacklist add/delete
- Model Performance dashboard
- Guarded model retraining

The backend runs on port `5001` because macOS may already use port `5000`.

## Tech Stack

### Frontend

- React
- Tailwind-style custom CSS
- Recharts
- Framer Motion
- Lucide React Icons
- React Toastify

### Backend and ML API

- Python
- Flask
- Flask-CORS
- Pandas
- NumPy
- Scikit-learn
- Random Forest Classifier
- StandardScaler

### Browser Extension

- Chrome Extension Manifest V3
- Background service worker
- Content script
- Popup UI

## Main Features

### 1. URL Phishing Detection

MAPIS analyzes:

- HTTPS usage
- URL length
- IP address usage
- Dot count
- Hyphens
- Subdomain depth
- Suspicious keywords
- Double slash attacks
- URL entropy
- Brand spoofing
- Page content signals from the extension

Output:

- Safe
- Suspicious
- Phishing
- Risk score
- Threat type
- Explanations

### 2. Email Phishing Detection

MAPIS analyzes:

- Sender address
- Sender domain pattern
- SPF
- DKIM
- DMARC
- Subject
- Email body
- Suspicious terms
- Urgency language
- Embedded links

### 3. Five Detection Layers

The dashboard uses these layers:

1. URL Analysis - Detects suspicious URL patterns and domain characteristics.
2. ML Analysis - Uses a Random Forest model to classify websites from extracted URL features.
3. Website Behavior Analysis - Examines webpage structure and form actions.
4. Content Analysis - Uses NLP-style checks for suspicious message or email content.
5. Sender Reputation Analysis - Evaluates domain and IP reputation signals.

### 4. Real-Time Alerts

When a phishing or suspicious result is found:

- An alert is added to the dashboard.
- The Chrome Extension warning popup appears on the website.
- The dashboard counters and charts update from real scan records.

### 5. Chrome Extension Warning Popup

When a user opens a risky website, the extension:

1. Reads the current tab URL.
2. Extracts page content signals.
3. Sends the URL and page signals to the Flask API.
4. Receives a canonical scan result.
5. Shows a MAPIS warning overlay with the same risk score used by the dashboard.

The extension now canonicalizes URLs, so these score the same:

```text
https://br-icloud.com.br
https://br-icloud.com.br/
```

### 6. Model Performance and Learning Guard

The Random Forest model is evaluated from the saved model and dataset.

Current verified metrics:

```text
Accuracy: 87.52%
Precision: 75.22%
```

The retraining script includes a Learning Guard:

- A candidate model is trained.
- The old and new models are tested on the same held-out split.
- The candidate is promoted only if held-out accuracy is not lower than the current model.
- Previous model and scaler files are backed up before promotion.

This prevents the displayed accuracy from decreasing after retraining.

## Project Structure

```text
MAIPS/
├── backend/
│   ├── app.py
│   ├── feature_extractor.py
│   ├── train_model.py
│   ├── test_api.py
│   ├── dataset.csv
│   ├── raw_urls.csv
│   ├── model.pkl
│   ├── scaler.pkl
│   └── model_metadata.json
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.js
│   │   └── App.css
│   ├── package.json
│   └── package-lock.json
│
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   └── icon.png
│
└── README.md
```

## Setup Instructions

### 1. Open Project

```bash
cd /Users/sanjanan/MAIPS
code .
```

### 2. Backend Setup

Use the existing backend virtual environment if it is already present:

```bash
cd backend
source venv/bin/activate
python app.py
```

If a fresh virtual environment is needed:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors pandas numpy scikit-learn
python app.py
```

Backend URL:

```text
http://127.0.0.1:5001
```

Health check:

```bash
curl http://127.0.0.1:5001/api/dashboard
```

### 3. Frontend Setup

Open a second terminal:

```bash
cd frontend
npm install
npm start
```

Frontend URL:

```text
http://localhost:3000
```

### 4. Chrome Extension Setup

1. Open Chrome.
2. Go to:

```text
chrome://extensions
```

3. Enable Developer mode.
4. Click Load unpacked.
5. Select:

```text
/Users/sanjanan/MAIPS/extension
```

6. Keep the Flask backend running on:

```text
http://127.0.0.1:5001
```

After changing extension files, click Reload on the extension card in `chrome://extensions`.

## Admin Login

Default development admin credentials:

```text
Email: admin@mapis.local
Password: Admin@123
```

These can be overridden using environment variables:

```bash
export MAPIS_ADMIN_EMAIL="your-admin@example.com"
export MAPIS_ADMIN_PASSWORD="YourStrongPassword"
```

## Common Commands

### Run Backend

```bash
cd backend
source venv/bin/activate
python app.py
```

### Run Frontend

```bash
cd frontend
npm start
```

### Build Frontend

```bash
cd frontend
npm run build
```

### Check Backend Syntax

```bash
cd backend
python -m py_compile app.py feature_extractor.py train_model.py test_api.py
```

### Check Extension Syntax

```bash
cd extension
node --check background.js
node --check content.js
node --check popup.js
```

### Retrain ML Model With Guard

```bash
cd backend
source venv/bin/activate
python train_model.py
```

The script writes:

```text
backend/model_metadata.json
backend/model.previous.pkl
backend/scaler.previous.pkl
```

It promotes the new model only when held-out accuracy is not lower.

## API Endpoints

### Dashboard

```http
GET /api/dashboard
```

### Model Metrics

```http
GET /api/model/metrics
```

### URL Scan

```http
POST /api/scan/url
```

Example body:

```json
{
  "url": "https://br-icloud.com.br"
}
```

### Latest URL Result

```http
GET /api/scan/latest?url=https://br-icloud.com.br
```

### Email Scan

```http
POST /api/scan/email
```

Example body:

```json
{
  "sender": "security@verify-account-login.xyz",
  "subject": "Urgent account verification required",
  "body": "Your account is suspended. Verify your password immediately.",
  "headers": "spf=fail; dkim=fail; dmarc=fail"
}
```

### Alerts

```http
GET /api/alerts
POST /api/alerts
```

### Blacklist

```http
GET /api/blacklist
POST /api/blacklist/add
DELETE /api/blacklist/:id
```

Blacklist add/delete requires admin authentication.

## Important Notes

- Dashboard numbers are based on real scan records, not fake static values.
- Development scan history is in memory, so it resets when the backend restarts.
- The Chrome Extension and dashboard both use backend port `5001`.
- If the warning popup score looks old, reload the extension in `chrome://extensions`.
- The ML model accuracy can improve after retraining, but the Learning Guard prevents promoting a lower-accuracy model.

## Resume Description

Built MAPIS, a full-stack phishing intelligence platform with URL and email analysis, Random Forest ML prediction, explainable risk scoring, live security dashboard, admin blacklist management, and Chrome Extension based real-time phishing warnings.
