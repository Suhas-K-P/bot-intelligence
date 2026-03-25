"""
BotShield — Analytics Module
==============================
Aggregation helpers that transform the classified DataFrame
into chart-ready payloads for the frontend.
"""

import pandas as pd
from classifier import extract_crawler_name


def count_by_type(df: pd.DataFrame) -> dict:
    counts = df["_type"].value_counts().to_dict()
    return {
        "human":   int(counts.get("human",   0)),
        "bad":     int(counts.get("bad",     0)),
        "ai":      int(counts.get("ai",      0)),
        "crawler": int(counts.get("crawler", 0)),
    }


def count_rules(df: pd.DataFrame, top_n: int = 12) -> list:
    """
    Returns [{"name": ..., "count": ..., "desc": ...}, ...]
    sorted by count descending.
    """
    from classifier import RULES
    rule_desc = {r["name"]: r["desc"] for r in RULES}

    counts = {}
    for rules_list in df["_rules"]:
        for rule in rules_list:
            counts[rule] = counts.get(rule, 0) + 1

    sorted_rules = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [
        {"name": name, "count": cnt, "desc": rule_desc.get(name, "")}
        for name, cnt in sorted_rules
    ]


def top_ai_crawlers(df: pd.DataFrame, top_n: int = 15) -> list:
    """
    Returns top AI crawlers by request count.
    [{"name": ..., "count": ..., "ua": ...}, ...]
    """
    ai_df = df[df["_type"] == "ai"].copy()
    if ai_df.empty:
        return []

    # Use crawler_type column if available, else extract from UA
    if "crawler_type" in ai_df.columns:
        ai_df["_crawler_name"] = ai_df["crawler_type"].fillna("").apply(
            lambda x: x if x.strip() else extract_crawler_name(ai_df.loc[ai_df.index == ai_df.index[0], "UA"].iloc[0] if not ai_df.empty else "")
        )
        # Fallback: if crawler_type is blank, extract from UA
        mask = ai_df["_crawler_name"].str.strip() == ""
        ai_df.loc[mask, "_crawler_name"] = ai_df.loc[mask, "UA"].apply(extract_crawler_name)
    else:
        ai_df["_crawler_name"] = ai_df["UA"].fillna("").apply(extract_crawler_name)

    grouped = (
        ai_df.groupby("_crawler_name")
        .agg(count=("_crawler_name", "count"), ua=("UA", "first"))
        .reset_index()
        .rename(columns={"_crawler_name": "name"})
        .sort_values("count", ascending=False)
        .head(top_n)
    )
    return grouped.to_dict(orient="records")


def fraud_score_distribution(df: pd.DataFrame, bins: int = 10) -> dict:
    """
    Returns a histogram of fraud scores for the bar chart.
    {"labels": [...], "values": [...]}
    """
    scores = df["fraud_score_ip"].fillna(0).astype(float)
    counts, edges = pd.cut(scores, bins=bins, retbins=True, labels=False)
    freq = counts.value_counts().sort_index()

    labels = [f"{int(edges[i])}–{int(edges[i+1])}" for i in range(len(edges)-1)]
    values = [int(freq.get(i, 0)) for i in range(len(labels))]
    return {"labels": labels, "values": values}


def ua_type_breakdown(df: pd.DataFrame) -> dict:
    """
    Browser vs Automation breakdown.
    {"labels": [...], "values": [...]}
    """
    automation = int(df["_bad_ua"].sum())
    browser    = len(df) - automation
    return {
        "labels": ["Browser", "Automation"],
        "values": [browser, automation],
        "colors": ["#00ff88", "#ff3b5c"],
    }
