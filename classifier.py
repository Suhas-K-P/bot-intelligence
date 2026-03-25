"""
BotShield — Classifier & Rule Engine
======================================
All detection rules and classification logic.
Add new rules by appending to the RULES list.
"""

import pandas as pd
import numpy as np

# ─────────────────────────────────────────────
# KNOWN UA FINGERPRINTS
# ─────────────────────────────────────────────

AI_UA_KEYWORDS = [
    "gptbot", "anthropic", "claude", "googlebot", "bingbot",
    "facebookexternalhit", "twitterbot", "linkedinbot", "applebot",
    "slurp", "duckduckbot", "baiduspider", "yandexbot", "semrushbot",
    "ahrefsbot", "mj12bot", "rogerbot", "dotbot", "bytespider",
    "amazonbot", "pinterestbot", "petalbot", "ccbot", "ia_archiver",
    "archive.org_bot", "exabot", "naverbot", "sogou", "openai",
    "cohere", "perplexitybot", "diffbot",
]

BAD_UA_KEYWORDS = [
    "curl", "wget", "python-requests", "python-urllib", "go-http-client",
    "java/", "scrapy", "postmanruntime", "node-fetch", "restsharp",
    "headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer",
    "httpie", "libwww-perl", "lwp-trivial", "mechanize",
]

CRAWLER_NAME_PATTERNS = [
    ("GPTBot",            r"(?i)GPTBot"),
    ("ClaudeBot",         r"(?i)ClaudeBot|anthropic"),
    ("PerplexityBot",     r"(?i)PerplexityBot"),
    ("Googlebot",         r"(?i)Googlebot"),
    ("Bingbot",           r"(?i)bingbot"),
    ("Facebook Crawler",  r"(?i)facebookexternalhit"),
    ("Twitterbot",        r"(?i)Twitterbot"),
    ("LinkedInBot",       r"(?i)LinkedInBot"),
    ("Applebot",          r"(?i)Applebot"),
    ("YandexBot",         r"(?i)YandexBot"),
    ("Baiduspider",       r"(?i)Baiduspider"),
    ("AhrefsBot",         r"(?i)AhrefsBot"),
    ("SemrushBot",        r"(?i)SemrushBot"),
    ("CCBot",             r"(?i)CCBot"),
    ("ByteSpider",        r"(?i)ByteSpider"),
    ("AmazonBot",         r"(?i)AmazonBot"),
    ("PetalBot",          r"(?i)PetalBot"),
    ("DuckDuckBot",       r"(?i)DuckDuckBot"),
    ("Yahoo Slurp",       r"(?i)Slurp"),
    ("Internet Archive",  r"(?i)ia_archiver|archive\.org_bot"),
]


# ─────────────────────────────────────────────
# RULE DEFINITIONS
# Each rule: dict with id, name, desc, and a
#            vectorised function: fn(df) → bool Series
# ─────────────────────────────────────────────

def _col(df, name, default=""):
    """Safely retrieve a column, returning a Series of defaults if missing."""
    return df[name] if name in df.columns else pd.Series(default, index=df.index)


RULES = [
    {
        "id":   "high_fraud_score",
        "name": "High Fraud Score",
        "desc": "IP fraud score exceeds 60",
        "fn":   lambda df: _col(df, "fraud_score_ip", 0).fillna(0).astype(float) > 60,
    },
    {
        "id":   "datacenter_ip",
        "name": "Datacenter IP",
        "desc": "Traffic from a cloud/hosting ASN (non-AI)",
        "fn":   lambda df: (
            _col(df, "is_datacenter", "False").astype(str).str.lower().isin(["true", "1"])
            & ~(_col(df, "isAIcrawler", "False").astype(str).str.lower().isin(["true", "1"]))
        ),
    },
    {
        "id":   "vpn_detected",
        "name": "VPN Detected",
        "desc": "Request routed through a VPN service",
        "fn":   lambda df: _col(df, "is_vpn", "False").astype(str).str.lower().isin(["true", "1"]),
    },
    {
        "id":   "tor_exit_node",
        "name": "TOR Exit Node",
        "desc": "Anonymized via TOR network",
        "fn":   lambda df: _col(df, "is_tor", "False").astype(str).str.lower().isin(["true", "1"]),
    },
    {
        "id":   "bad_user_agent",
        "name": "Bad User-Agent",
        "desc": "Script / automation tool UA detected",
        "fn":   lambda df: _col(df, "UA", "").str.lower().str.contains(
            "|".join(BAD_UA_KEYWORDS), na=False
        ),
    },
    {
        "id":   "missing_headers",
        "name": "Missing Headers",
        "desc": "Accept-Language header is absent",
        "fn":   lambda df: _col(df, "accept_language", "").fillna("").str.strip() == "",
    },
    {
        "id":   "no_session_cookie",
        "name": "No Session Cookie",
        "desc": "No valid session cookie found",
        "fn":   lambda df: _col(df, "cookie1", "").fillna("").astype(str).str.strip().isin(["", "None", "nan"]),
    },
    {
        "id":   "ai_crawler_ua",
        "name": "AI Crawler UA",
        "desc": "Matches a known AI/LLM crawler UA pattern",
        "fn":   lambda df: _col(df, "UA", "").str.lower().str.contains(
            "|".join(AI_UA_KEYWORDS), na=False
        ),
    },
    {
        "id":   "headless_webgl",
        "name": "Headless WebGL",
        "desc": "SwiftShader GPU — indicates headless Chrome",
        "fn":   lambda df: _col(df, "webgl", "").str.contains("SwiftShader", na=False),
    },
    {
        "id":   "linux_server_platform",
        "name": "Linux Server Platform",
        "desc": "Linux x86_64 + non-legit request",
        "fn":   lambda df: (
            (_col(df, "navigator_platform", "") == "Linux x86_64")
            & ~(_col(df, "islegit", "False").astype(str).str.lower().isin(["true", "1"]))
        ),
    },
    {
        "id":   "mismatched_fetch_headers",
        "name": "Mismatched Fetch Headers",
        "desc": "sec-fetch-site/mode inconsistency",
        "fn":   lambda df: (
            (_col(df, "sec_fetch_site", "").fillna("") == "")
            & (_col(df, "sec_fetch_mode", "").fillna("") == "")
        ),
    },
    {
        "id":   "utc_timezone",
        "name": "UTC Server Timezone",
        "desc": "UTC timezone — common cloud bot indicator",
        "fn":   lambda df: (
            (_col(df, "timezone", "") == "UTC")
            & ~(_col(df, "islegit", "False").astype(str).str.lower().isin(["true", "1"]))
        ),
    },
]


# ─────────────────────────────────────────────
# CLASSIFIER
# ─────────────────────────────────────────────

def classify_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Runs all rules and traffic-type classification on a DataFrame.
    Adds _type, _rules, and helper bool columns.
    Returns the enriched DataFrame.
    """
    df = df.copy()

    # Boolean helper columns
    df["_is_ai"]      = _col(df, "isAIcrawler", "False").astype(str).str.lower().isin(["true", "1"])
    df["_is_legit"]   = _col(df, "islegit",     "False").astype(str).str.lower().isin(["true", "1"])
    df["_is_crawler"] = _col(df, "iscrawler",   "False").astype(str).str.lower().isin(["true", "1"])
    df["_is_dc"]      = _col(df, "is_datacenter","False").astype(str).str.lower().isin(["true", "1"])
    df["_is_vpn"]     = _col(df, "is_vpn",      "False").astype(str).str.lower().isin(["true", "1"])
    df["_is_tor"]     = _col(df, "is_tor",       "False").astype(str).str.lower().isin(["true", "1"])
    df["_bad_ua"]     = _col(df, "UA", "").str.lower().str.contains("|".join(BAD_UA_KEYWORDS), na=False)
    df["_missing_headers"] = _col(df, "accept_language", "").fillna("").str.strip() == ""
    df["fraud_score_ip"]   = _col(df, "fraud_score_ip", 0).fillna(0).astype(float)

    # Run all rules — store triggered rule names per row
    rule_hits = {}
    for rule in RULES:
        rule_hits[rule["name"]] = rule["fn"](df)

    df["_rules"] = [
        [name for name, mask in rule_hits.items() if mask.iloc[i]]
        for i in range(len(df))
    ]

    # Classify traffic type
    conditions = [
        df["_is_ai"],
        df["_is_legit"],
        df["_is_crawler"] | df["_bad_ua"] | (df["fraud_score_ip"] > 60) | df["_is_tor"],
    ]
    choices = ["ai", "human", "bad"]
    df["_type"] = np.select(conditions, choices, default="crawler")

    return df


def compute_risk_score(df: pd.DataFrame) -> int:
    """Overall threat risk score 0-100."""
    total = len(df)
    if total == 0:
        return 0
    bad_pct    = len(df[df["_type"].isin(["bad", "ai"])]) / total
    tor_pct    = df["_is_tor"].sum() / total
    vpn_pct    = df["_is_vpn"].sum() / total
    avg_fraud  = df["fraud_score_ip"].mean()
    score = bad_pct * 50 + tor_pct * 30 + vpn_pct * 10 + avg_fraud * 0.1
    return min(100, round(score))


def build_timeline(df: pd.DataFrame, buckets: int = 20) -> list:
    """Group rows into time buckets for the stacked timeline chart."""
    if "recvdTime" not in df.columns:
        return []
    ts = pd.to_numeric(df["recvdTime"], errors="coerce").dropna()
    if ts.empty:
        return []

    min_t, max_t = ts.min(), ts.max()
    size = max(1, (max_t - min_t) / buckets)

    result = []
    for i in range(buckets):
        bucket_min = min_t + i * size
        bucket_max = bucket_min + size
        mask = (pd.to_numeric(df["recvdTime"], errors="coerce") >= bucket_min) & \
               (pd.to_numeric(df["recvdTime"], errors="coerce") <  bucket_max)
        subset = df[mask]
        import datetime
        label = datetime.datetime.utcfromtimestamp(bucket_min).strftime("%d %b")
        result.append({
            "label":   label,
            "human":   int((subset["_type"] == "human").sum()),
            "bad":     int((subset["_type"] == "bad").sum()),
            "ai":      int((subset["_type"] == "ai").sum()),
            "crawler": int((subset["_type"] == "crawler").sum()),
        })
    return result


def extract_crawler_name(ua: str) -> str:
    """Map a UA string to a human-readable crawler name."""
    import re
    for name, pattern in CRAWLER_NAME_PATTERNS:
        if re.search(pattern, ua or ""):
            return name
    m = re.search(r"([A-Z][a-zA-Z0-9]+[Bb]ot)", ua or "")
    return m.group(1) if m else "Unknown Crawler"
