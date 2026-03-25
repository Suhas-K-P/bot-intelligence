#  Bot Intelligence: Real-Time Detection & Threat Analysis Engine

A full-stack bot traffic analysis system that helps detect malicious traffic, analyze behavior, and uncover fraud signals in real time.

Upload any traffic CSV → get instant insights into:

- Bot activity  
- Fraud signals  
- Behavioral patterns  

---

## 📁 Project Structure

```bash
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
```

---

## ⚙️ Setup & Run

### 1. Clone & Navigate

```bash
cd Bot_Intelligence
```

### 2. Create Virtual Environment (Optional)

```bash
python -m venv venv
```

#### Activate Environment

**Windows**
```bash
venv\Scripts\activate
```

**Linux / Mac**
```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Server

```bash
python app.py
```

### 5. Open in Browser

```bash
http://localhost:5000
```

---

## 📊 Features

- Real-time bot detection from traffic logs  
- Rule-based classification engine  
- Fraud scoring and risk analysis  
- AI crawler detection (GPTBot, Claude, etc.)  
- TOR / VPN / Datacenter detection  
- Interactive dashboard with charts  
- CSV upload and analysis pipeline  

---

## 🧠 Detection Signals

The system identifies bots using:

- High fraud score patterns  
- Suspicious IP behavior  
- Automation tools (Selenium, Playwright)  
- Missing headers or abnormal requests  
- Headless browser fingerprints  
- AI crawler identification  
- Network anomalies (TOR, VPN)  

---

## 🔌 API Endpoint

| Method | Endpoint   | Description                          |
|--------|-----------|--------------------------------------|
| POST   | /analyze  | Upload CSV and get analysis results |

### Example

```bash
curl -X POST http://localhost:5000/analyze \
     -F "file=@your_file.csv"
```

---

## ➕ Adding Custom Rules

Modify `classifier.py`:

```python
{
    "id": "custom_rule",
    "name": "Custom Rule",
    "desc": "Description of rule",
    "fn": lambda df: df["column"].str.contains("pattern", na=False),
}
```

---

## 💡 Future Improvements

- ML-based anomaly detection  
- Geo-IP enrichment  
- Real-time streaming pipeline  
- Advanced fingerprinting  

---

## 🤝 Contributing

Contributions are welcome. Feel free to open issues or submit pull requests.


