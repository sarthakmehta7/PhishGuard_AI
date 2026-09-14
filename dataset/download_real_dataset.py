"""
Download a REAL labelled training dataset from public threat-intelligence sources.
No synthetic phishing URLs are generated.

Labels:
0 = Legitimate/popular domain sample (Tranco)
1 = Suspicious/malicious URL (URLhaus)
2 = Verified phishing URL (OpenPhish)
"""
from pathlib import Path
import io, csv, zipfile, requests, pandas as pd
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
OUT = BASE / "phishing_dataset.csv"
TIMEOUT = 30
HEADERS = {"User-Agent": "PhishGuard-AI-College-Project/1.0"}

def get_text(url):
    r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    r.raise_for_status()
    return r.text

def openphish(limit=5000):
    text = get_text("https://openphish.com/feed.txt")
    urls = []
    for line in text.splitlines():
        u = line.strip()
        if u.startswith(("http://", "https://")):
            urls.append(u)
        if len(urls) >= limit: break
    return urls

def urlhaus(limit=5000):
    text = get_text("https://urlhaus.abuse.ch/downloads/csv_recent/")
    urls = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#") or len(row) < 3: continue
        u = row[2].strip()
        if u.startswith(("http://", "https://")):
            urls.append(u)
        if len(urls) >= limit: break
    return urls

def tranco(limit=5000):
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=TIMEOUT, headers=HEADERS)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    name = z.namelist()[0]
    urls = []
    with z.open(name) as f:
        for raw in io.TextIOWrapper(f, encoding="utf-8"):
            parts = raw.strip().split(",", 1)
            if len(parts) != 2: continue
            domain = parts[1].strip()
            if domain:
                urls.append("https://" + domain)
            if len(urls) >= limit: break
    return urls

def main():
    print("="*60)
    print("PhishGuard AI — REAL DATASET DOWNLOADER")
    print("="*60)
    sources = []
    errors = []
    for name, label, fn in [
        ("Tranco popular domains", 0, tranco),
        ("URLhaus malicious URLs", 1, urlhaus),
        ("OpenPhish verified phishing URLs", 2, openphish),
    ]:
        try:
            rows = fn()
            print(f"[OK] {name}: {len(rows)} samples")
            sources.extend({"url": u, "label": label, "source": name} for u in rows)
        except Exception as e:
            errors.append(f"{name}: {e}")
            print(f"[WARN] {name} download failed: {e}")

    if not sources:
        raise SystemExit("No real data could be downloaded. Check your internet connection.")

    df = pd.DataFrame(sources).drop_duplicates(subset=["url"], keep="first")
    counts = df["label"].value_counts().to_dict()
    # Require at least two classes; never silently invent missing data.
    if len(counts) < 2:
        raise SystemExit(f"Not enough classes downloaded: {counts}. Try again later.")

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(OUT, index=False)
    print(f"\nSaved {len(df)} REAL sourced samples to: {OUT}")
    print("Distribution:", counts)
    if errors:
        print("\nSome sources were unavailable; this is reported rather than replaced with fake data:")
        for e in errors: print(" -", e)

if __name__ == "__main__":
    main()
