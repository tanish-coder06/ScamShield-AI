🛡️ ScamShield AI

AI-assisted scam and phishing awareness platform
Team: Epoch Enders · Team Number: A 147

ScamShield AI is a web application that helps users examine suspicious messages and URLs. It uses machine-learning predictions and safety guidance to highlight patterns that may be associated with phishing or digital scams.

Important: ScamShield AI is an experimental awareness tool. Its predictions can be wrong and are not a guarantee that a message or website is safe or malicious. Always verify unexpected requests and links through official channels.

✨ Features

Message Scanner — submit a suspicious message for analysis and receive a prediction, explanation, and recommended safety actions.

URL Scanner — analyze URL patterns using a trained machine-learning classifier without opening the submitted website.

Dashboard — navigate between scanning tools and safety guidance.

Recent Scan History — keeps up to 10 recent entries in browser localStorage.

Safety Recommendations — provides practical reminders for handling suspicious links and messages.

Cybersecurity-themed UI — dark interface styling with cyan/blue accents and responsive layout.

🧰 Tech Stack

Frontend: React, Vite, CSS

Backend: Python, FastAPI

Machine Learning: scikit-learn and engineered URL-string features

Data: UCI PhiUSIIL phishing URL dataset (used by the URL model training pipeline)

Local history: Browser localStorage

🗂️ Project Structure

ScamShieldAI/
├── backend/
│   ├── main.py
│   ├── url_analyzer.py
│   ├── inspect_url_dataset.py
│   ├── model/
│   │   └── url_model.joblib
│   └── venv/                  # local virtual environment; don't commit
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── App.css
    │   └── components/
    │       └── URLScanner.jsx
    ├── package.json
    └── ...

The exact file list may vary depending on your local setup. Do not commit virtual environments, API keys, secrets, or unnecessary large datasets.

🚀 Run Locally

You need Python and Node.js/npm installed.

1. Start the backend

Open a terminal in the project folder and run:

cd backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload

The API should run at http://127.0.0.1:8000.

If PowerShell blocks activation, you can run the backend with the virtual environment's Python directly:

.\venv\Scripts\python.exe -m uvicorn main:app --reload

2. Start the frontend

Open a second terminal:

cd frontend
npm install
npm run dev

Open the local URL printed by Vite, typically http://localhost:5173.

Keep both terminals running while using the application.

🔎 How to Use

Open the ScamShield AI dashboard.

Choose Message Scanner to submit a suspicious message.

Choose URL Scanner to analyze a URL.

Review the prediction, explanation, and recommended actions.

Visit Recent Scan History to review recent entries; use Clear History to remove them.

🧠 How URL Analysis Works

The URL model uses engineered URL-string features, which can include URL and hostname length, IP-address presence, subdomain structure, character counts/ratios, and HTTPS presence. The backend passes these features to the trained classifier and returns a prediction and guidance to the frontend.

This is pattern-based analysis—not a live reputation check. The application does not independently verify the site's ownership, content, or current reputation, and it does not open the submitted URL.

⚠️ Current Limitations

Predictions may produce false positives or false negatives.

A low-risk or non-phishing prediction does not prove a site is safe.

URL analysis currently focuses on URL-string features and does not inherently verify live domain reputation.

Scan history is stored in the current browser, not a shared database, and is limited to recent entries.

This is a prototype for awareness and demonstration, not a replacement for professional security software.

🔮 Future Improvements

Integrate reputable domain-reputation and threat-intelligence services.

Evaluate models on independent, recent datasets and improve false-positive handling.

Expand message detection across more languages and scam patterns.

Add OCR for screenshots and QR-code analysis.

Add database-backed history, export controls, and optional user accounts.

Improve accessibility, mobile layouts, and multilingual safety guidance.

Add deployment hardening, rate limiting, monitoring, and privacy controls.


📄 License

No license has been specified yet. Add a LICENSE file before presenting this repository as open source under a particular license.
