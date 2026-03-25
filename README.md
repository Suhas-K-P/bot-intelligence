# BotShield — Python Edition 🛡️

A full-stack **Python + Flask** bot traffic classifier.
Upload any traffic CSV → get instant bot intelligence.

---

## Folder Structure

```
botshield_py/
├── app.py              ← Flask server (entry point)
├── classifier.py       ← Rule engine + classification logic
├── analytics.py        ← Aggregation helpers for charts
├── requirements.txt    ← pip dependencies
├── templates/
│   └── index.html      ← Jinja2 HTML template
└── static/
    ├── css/
    │   └── style.css   ← Dark cyber theme
    └── js/
        └── dashboard.js ← Chart.js frontend logic
```

---

## Setup & Run

```bash
# 1. Navigate to the folder
cd botshield_py

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux / Mac
venv\Scripts\activate.bat       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
python app.py

# 5. Open your browser
# → http://localhost:5000
```

---

## Generate Test Data

Use your existing generator script:

```bash
pip install faker openpyxl
python generate_traffic.py
# Produces: final_traffic_8000.csv
```

Upload that CSV to BotShield.

---

## Detection Rules

| Rule | Signal |
|---|---|
| High Fraud Score | `fraud_score_ip > 60` |
| Datacenter IP | `is_datacenter = True` (non-AI) |
| VPN Detected | `is_vpn = True` |
| TOR Exit Node | `is_tor = True` |
| Bad User-Agent | curl, scrapy, Selenium, Playwright, etc. |
| Missing Headers | `accept_language` empty |
| No Session Cookie | `cookie1` is null/empty |
| AI Crawler UA | GPTBot, ClaudeBot, Googlebot, etc. |
| Headless WebGL | `webgl = Google SwiftShader` |
| Linux Server Platform | `navigator_platform = Linux x86_64` + not legit |
| Mismatched Fetch Headers | `sec_fetch_site/mode` inconsistency |
| UTC Server Timezone | `timezone = UTC` + not legit |

---

## Adding Custom Rules

Open `classifier.py` and add to the `RULES` list:

```python
{
    "id":   "my_rule",
    "name": "My Custom Rule",
    "desc": "Short description for the dashboard",
    "fn":   lambda df: df["some_column"].fillna("").str.contains("pattern"),
},
```

The frontend picks it up automatically — no other changes needed.

---

## API Endpoint

| Method | URL | Body | Response |
|---|---|---|---|
| POST | `/analyze` | `multipart/form-data` with `file` field | JSON with full analysis |

You can also hit the API directly:
```bash
curl -X POST http://localhost:5000/analyze \
     -F "file=@final_traffic_8000.csv"
```
