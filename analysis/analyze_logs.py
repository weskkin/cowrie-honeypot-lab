#!/usr/bin/env python3
"""
CyberTrap Threat Intelligence Analyzer with GeoIP Enrichment
Parses Cowrie JSON logs, enriches IPs with Country/ASN, and generates charts.
"""

import json
import os
import sys
import time
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
import urllib.request

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "cowrie.json")
FIG_DIR = os.path.join(BASE_DIR, "figures")
REPORT_FILE = os.path.join(BASE_DIR, "threat_summary.txt")
GEO_CACHE_FILE = os.path.join(BASE_DIR, "geoip_cache.json")

os.makedirs(FIG_DIR, exist_ok=True)

print("=" * 65)
print("🍯 CYBERTRAP THREAT INTELLIGENCE ANALYZER + GEOIP ENRICHMENT")
print("=" * 65)

if not os.path.exists(LOG_FILE):
    print(f"[-] Error: Could not find log file at {LOG_FILE}")
    sys.exit(1)

print(f"[*] Loading logs from: {LOG_FILE}")

# 1. Load JSON lines
records = []
total_lines = 0

with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        total_lines += 1
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

print(f"[+] Loaded {len(records):,} valid events.")

df = pd.DataFrame(records)

# Ensure essential columns
for col in ["eventid", "src_ip", "timestamp", "username", "password", "input", "shasum"]:
    if col not in df.columns:
        df[col] = None

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

total_events = len(df)
unique_ips = df["src_ip"].dropna().unique()
unique_sessions = df["session"].dropna().nunique() if "session" in df.columns else 0

print(f"[+] Unique Threat Actors (IPs): {len(unique_ips):,}")
print(f"[+] Unique Sessions:           {unique_sessions:,}")

# 2. GeoIP Enrichment with local caching
print("\n[*] Performing GeoIP enrichment on unique IPs...")
geo_cache = {}
if os.path.exists(GEO_CACHE_FILE):
    try:
        with open(GEO_CACHE_FILE, "r", encoding="utf-8") as f:
            geo_cache = json.load(f)
        print(f"[+] Loaded {len(geo_cache)} cached GeoIP lookups.")
    except Exception:
        geo_cache = {}

# Query ip-api.com for uncached IPs in batches of 100
uncached = [ip for ip in unique_ips if ip and ip not in geo_cache and not ip.startswith(("10.", "192.168.", "172.16.", "127."))]

if uncached:
    print(f"[*] Querying GeoIP for {len(uncached)} new IP addresses (batch API)...")
    batch_size = 100
    for i in range(0, len(uncached), batch_size):
        chunk = uncached[i:i + batch_size]
        try:
            req_data = json.dumps([{"query": ip, "fields": "query,status,country,countryCode,city,org,as"} for ip in chunk]).encode("utf-8")
            req = urllib.request.Request("http://ip-api.com/batch", data=req_data, headers={"User-Agent": "CyberTrap-Honeypot-Lab"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read().decode("utf-8"))
                for res in results:
                    ip = res.get("query")
                    if res.get("status") == "success":
                        geo_cache[ip] = {
                            "country": res.get("country", "Unknown"),
                            "countryCode": res.get("countryCode", "??"),
                            "city": res.get("city", "Unknown"),
                            "org": res.get("org", "Unknown"),
                            "as": res.get("as", "Unknown"),
                        }
                    else:
                        geo_cache[ip] = {"country": "Unknown", "countryCode": "??", "city": "Unknown", "org": "Unknown", "as": "Unknown"}
            time.sleep(1.5)  # Rate limiting respect
        except Exception as e:
            print(f"[-] GeoIP batch lookup notice: {e}")
            for ip in chunk:
                if ip not in geo_cache:
                    geo_cache[ip] = {"country": "Unknown", "countryCode": "??", "city": "Unknown", "org": "Unknown", "as": "Unknown"}

    with open(GEO_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(geo_cache, f, indent=2)
    print("[+] GeoIP cache updated.")

# Map GeoIP data back to dataframe
df["country"] = df["src_ip"].map(lambda ip: geo_cache.get(ip, {}).get("country", "Unknown"))
df["org"] = df["src_ip"].map(lambda ip: geo_cache.get(ip, {}).get("org", "Unknown"))

# Aggregations
top_ips = df["src_ip"].value_counts().head(10)
top_countries = df["country"].value_counts().head(10)
top_orgs = df["org"].value_counts().head(10)

login_events = df[df["eventid"].isin(["cowrie.login.failed", "cowrie.login.success"])]
top_users = login_events["username"].value_counts().head(10)
top_passwords = login_events["password"].value_counts().head(10)
top_combos = (login_events["username"].fillna("") + ":" + login_events["password"].fillna("")).value_counts().head(10)

cmd_events = df[df["eventid"] == "cowrie.command.input"]
top_cmds = cmd_events["input"].value_counts().head(15)

download_events = df[df["eventid"] == "cowrie.session.file_download"]
captured_files = []
if not download_events.empty and "shasum" in download_events.columns:
    captured_files = download_events[["shasum", "url", "src_ip"]].dropna(subset=["shasum"]).drop_duplicates()

# 3. Visualizations
print("\n[*] Generating high-resolution figures in analysis/figures/...")
plt.style.use("ggplot")

# Chart 1: Top Attacking Countries
plt.figure(figsize=(10, 5))
top_countries.plot(kind="bar", color="#e94560")
plt.title("Top 10 Source Countries of Attack Traffic")
plt.xlabel("Country")
plt.ylabel("Total Events")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(FIG_DIR, "top_attacking_countries.png"), dpi=200)
plt.close()

# Chart 2: Top Attacking IPs
plt.figure(figsize=(10, 5))
top_ips.plot(kind="barh", color="#0f3460").invert_yaxis()
plt.title("Top 10 Attacking IP Addresses")
plt.xlabel("Number of Events")
plt.ylabel("Source IP")
plt.tight_layout()
plt.savefig(os.path.join(FIG_DIR, "top_attacking_ips.png"), dpi=200)
plt.close()

# Chart 3: Top Targeted Usernames
plt.figure(figsize=(10, 5))
top_users.plot(kind="bar", color="#118ab2")
plt.title("Top 10 Targeted Usernames")
plt.xlabel("Username")
plt.ylabel("Attempts")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(FIG_DIR, "top_usernames.png"), dpi=200)
plt.close()

# Chart 4: Top Passwords
plt.figure(figsize=(10, 5))
top_passwords.plot(kind="bar", color="#ffd166")
plt.title("Top 10 Attempted Passwords")
plt.xlabel("Password")
plt.ylabel("Attempts")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(FIG_DIR, "top_passwords.png"), dpi=200)
plt.close()

# Chart 5: Attack Activity Timeline (Hourly)
if df["timestamp"].notnull().any():
    plt.figure(figsize=(12, 5))
    timeline = df.set_index("timestamp").resample("1h")["eventid"].count()
    timeline.plot(kind="line", color="#e94560", marker="o", linewidth=2)
    plt.title("Attack Activity Timeline (Events per Hour)")
    plt.xlabel("Time (UTC)")
    plt.ylabel("Total Events")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "attack_timeline.png"), dpi=200)
    plt.close()

print(f"[+] All charts saved to {FIG_DIR}/")

# 4. Save Final Threat Report
report_text = f"""
============================================================
              CYBERTRAP THREAT INTELLIGENCE REPORT
============================================================

1. OVERVIEW METRICS:
   - Total Analyzed Events:       {total_events:,}
   - Unique Threat Actors (IPs):   {len(unique_ips):,}
   - Total Attacker Sessions:     {unique_sessions:,}
   - Captured Malware Payloads:   {len(captured_files):,}

2. GEOGRAPHICAL ATTACK DISTRIBUTION (TOP COUNTRIES):
{top_countries.to_string()}

3. TOP 10 ATTACKING NETWORKS / ASNs:
{top_orgs.to_string()}

4. TOP 10 ATTACKING IP ADDRESSES:
{top_ips.to_string()}

5. TOP 10 TARGETED USERNAMES:
{top_users.to_string()}

6. TOP 10 ATTEMPTED PASSWORDS:
{top_passwords.to_string()}

7. TOP 10 USERNAME:PASSWORD COMBINATIONS:
{top_combos.to_string()}

8. TOP EXECUTED COMMANDS (POST-EXPLOITATION):
{top_cmds.to_string() if not top_cmds.empty else '   No shell commands logged.'}

9. CAPTURED MALWARE SAMPLES (SHA-256):
{captured_files.to_string(index=False) if not captured_files.empty else '   No download hashes captured.'}

============================================================
"""

print(report_text)

with open(REPORT_FILE, "w", encoding="utf-8") as f:
    f.write(report_text)

print(f"[+] Text report saved to {REPORT_FILE}")
