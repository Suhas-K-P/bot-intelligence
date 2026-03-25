
"""
Bot Intelligence: Real-Time Detection & Threat Analysis Engine
=================================
Run:
    pip install flask pandas
    python app.py

Then open: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify
import pandas as pd
import json
import os

from classifier import classify_dataframe, compute_risk_score, build_timeline
from analytics  import (
    count_by_type, count_rules, top_ai_crawlers,
    fraud_score_distribution, ua_type_breakdown,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accepts a CSV upload, classifies every row,
    and returns the full analysis as JSON.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename.endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file"}), 400

    try:
        df = pd.read_csv(f)
    except Exception as e:
        return jsonify({"error": f"Could not parse CSV: {e}"}), 400

    # Run classifier
    df = classify_dataframe(df)

    total  = len(df)
    counts = count_by_type(df)

    result = {
        "total":    total,
        "counts":   counts,

        # Stat cards
        "avg_fraud":  round(df["fraud_score_ip"].fillna(0).astype(float).mean(), 1),
        "tor_count":  int(df["_is_tor"].sum()),
        "vpn_count":  int(df["_is_vpn"].sum()),

        # Charts
        "donut": {
            "labels": ["Human", "Bad Bot", "AI Crawler", "Crawler"],
            "values": [counts["human"], counts["bad"], counts["ai"], counts["crawler"]],
            "colors": ["#00ff88", "#ff3b5c", "#b56dff", "#ffb800"],
        },

        "timeline":     build_timeline(df),
        "top_crawlers": top_ai_crawlers(df),
        "top_rules":    count_rules(df),
        "risk_score":   compute_risk_score(df),

        "fraud_dist":   fraud_score_distribution(df),
        "ua_breakdown": ua_type_breakdown(df),

        # Flagged rows table (first 500)
        "rows": build_rows_payload(df),
    }

    return jsonify(result)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def build_rows_payload(df: pd.DataFrame, limit: int = 500) -> list:
    cols = ["_type", "ip", "UA", "fraud_score_ip",
            "_is_dc", "_is_vpn", "_is_tor", "_bad_ua", "_missing_headers", "_rules"]
    available = [c for c in cols if c in df.columns]
    subset = df[available].head(limit)

    rows = []
    for _, r in subset.iterrows():
        rows.append({
            "type":            r.get("_type", ""),
            "ip":              str(r.get("ip", "—")),
            "ua":              str(r.get("UA", "—")),
            "fraud":           int(r.get("fraud_score_ip", 0) or 0),
            "datacenter":      bool(r.get("_is_dc", False)),
            "vpn":             bool(r.get("_is_vpn", False)),
            "tor":             bool(r.get("_is_tor", False)),
            "bad_ua":          bool(r.get("_bad_ua", False)),
            "missing_headers": bool(r.get("_missing_headers", False)),
            "rules":           r.get("_rules", []),
        })
    return rows


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # default 5000 locally
    app.run(host="0.0.0.0", port=port)
