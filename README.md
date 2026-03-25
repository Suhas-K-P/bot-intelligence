Bot Intelligence: Real-Time Detection & Threat Analysis Engine

A full-stack bot traffic analysis system that helps detect malicious traffic, analyze behavior, and uncover fraud signals in real time.

Upload any traffic CSV → get instant insights into:

Bot activity
Fraud signals
Behavioral patterns
📁 Project Structure
Bot_Intelligence/
│
├── app.py              # Backend server (entry point)
├── classifier.py       # Rule engine + classification logic
├── analytics.py        # Aggregation helpers for charts
├── requirements.txt    # Dependencies
│
├── templates/
│   └── index.html      # Frontend UI (Jinja2)
│
└── static/
    ├── css/
    │   └── style.css   # UI styling
    └── js/
        └── dashboard.js  # Dashboard logic
⚙️ Setup & Run
1. Clone & Navigate
cd Bot_Intelligence
2. Create Virtual Environment (Optional)
python -m venv venv
Activate Environment

Windows

venv\Scripts\activate

Linux / Mac

source venv/bin/activate
3. Install Dependencies
pip install -r requirements.txt
4. Run the Server
python app.py
5. Open in Browser
http://localhost:5000
📊 Features
Real-time bot detection from traffic logs
Rule-based classification engine
Fraud scoring and risk analysis
AI crawler detection (GPTBot, Claude, etc.)
TOR / VPN / Datacenter detection
Interactive dashboard with charts
CSV upload and analysis pipeline
🧠 Detection Signals

The system identifies bots using:

High fraud score patterns
Suspicious IP behavior
Automation tools (Selenium, Playwright)
Missing headers or abnormal requests
Headless browser fingerprints
AI crawler identification
Network anomalies (TOR, VPN)
🔌 API Endpoint
Method	Endpoint	Description
POST	/analyze	Upload CSV and get analysis results
Example
curl -X POST http://localhost:5000/analyze \
     -F "file=@your_file.csv"
➕ Adding Custom Rules

Modify classifier.py:

{
    "id": "custom_rule",
    "name": "Custom Rule",
    "desc": "Description of rule",
    "fn": lambda df: df["column"].str.contains("pattern", na=False),
}