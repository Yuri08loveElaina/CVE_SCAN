import os, sys, threading, requests, json, gzip, subprocess, smtplib, time
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify

# ------------- Config -------------
CONFIG = {
    "targets": ["192.168.1.10"],

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
    "github_token": None,  # nếu có thì điền token GitHub ở đây
}
log_data = []

# ------------ Docker runner -------------
def run_in_docker(filename, target):
    folder = os.path.abspath(os.path.dirname(filename))
    basefile = os.path.basename(filename)
    ext = os.path.splitext(basefile)[1].lower()
    # Các lệnh tương ứng từng ngôn ngữ
    if ext in [".py"]:
        cmd = ["python3", basefile, target]
    elif ext in [".sh"]:
        cmd = ["bash", basefile, target]
    elif ext in [".pl"]:
        cmd = ["perl", basefile, target]
    elif ext in [".php"]:
        cmd = ["php", basefile, target]
    elif ext in [".rb"]:
        cmd = ["ruby", basefile, target]
    elif ext in [".js"]:
        cmd = ["node", basefile, target]
    elif ext in [".ps1"]:
        cmd = ["powershell", "-File", basefile, target]
    elif ext in [".bat"]:
        cmd = [basefile, target]  # chỉ chạy trên Windows Docker image
    elif ext in [".jar"]:
        cmd = ["java", "-jar", basefile, target]
    else:
        print(f"[!] Unsupported exploit file extension {ext}")
        return ""

    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{folder}:/exploits",
        "-w", "/exploits",
        "exploit-runner"
    ] + cmd
    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=300)
        return result.stdout + result.stderr
    except Exception as e:
        print(f"[!] Error running exploit in docker: {e}")
        return ""

# ------------- Email alert -------------
def send_email(subject, body):
    if not CONFIG["email"]["enabled"]:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = CONFIG["email"]["from_addr"]
        msg['To'] = ", ".join(CONFIG["email"]["to_addrs"])

        server = smtplib.SMTP(CONFIG["email"]["smtp_server"], CONFIG["email"]["smtp_port"])
        server.starttls()
        server.login(CONFIG["email"]["username"], CONFIG["email"]["password"])
        server.sendmail(CONFIG["email"]["from_addr"], CONFIG["email"]["to_addrs"], msg.as_string())
        server.quit()
        print("[i] Email alert sent.")
    except Exception as e:
        print(f"[!] Email send error: {e}")

# ------------- Discord alert -------------
def send_discord(message):
    if not CONFIG["discord"]["enabled"]:
        return
    url = CONFIG["discord"]["webhook_url"]
    try:
        r = requests.post(url, json={"content": message})
        if r.status_code == 204:
            print("[i] Discord alert sent.")
        else:
            print(f"[!] Discord webhook error: {r.status_code}")
    except Exception as e:
        print(f"[!] Discord send error: {e}")

def send_alert(cve, output):
    message = f"Exploit successful for {cve}:\n```\n{output[:1000]}\n```"
    send_email(f"[ALERT] Exploit success: {cve}", output)
    send_discord(message)

# ------------- NVD data download and parse -------------
def download_nvd_bulk():
    url = CONFIG["nvd_bulk_url"]
    print("[i] Downloading NVD data from", url)
    try:
        r = requests.get(url, timeout=60)
        if r.status_code == 200:
            with open("nvd_data.json.gz", "wb") as f:
                f.write(r.content)
            with gzip.open("nvd_data.json.gz", 'rb') as f_in:
                with open("nvd_data.json", "wb") as f_out:
                    f_out.write(f_in.read())
            print("[i] NVD data saved to nvd_data.json")
            return True
        else:
            print("[!] Failed to download NVD data:", r.status_code)
            return False
    except Exception as e:
        print("[!] Exception downloading NVD data:", e)
        return False

def parse_nvd_cve_description(nvd_file, cve_id):
    try:
        with open(nvd_file) as f:
            data = json.load(f)
        for item in data.get("CVE_Items", []):
            if item["cve"]["CVE_data_meta"]["ID"] == cve_id:
                descs = item["cve"]["description"]["description_data"]
                if descs:
                    return descs[0]["value"]
    except Exception as e:
        print("[!] Parse NVD CVE error:", e)
    return ""

# ------------- Detect OS from CVE description (đơn giản) -------------
def detect_os_from_description(desc):
    desc = desc.lower()
    if "windows" in desc:
        return "Windows"
    if "linux" in desc:
        return "Linux"
    if "unix" in desc:
        return "Unix"
    if "mac os" in desc or "macos" in desc:
        return "MacOS"
    return "Unknown"

# ------------- Exploit-DB search & download -------------
def search_exploitdb(cve_id):
    try:
        url = f"https://www.exploit-db.com/search?cve={cve_id}"
        r = requests.get(url)
        if r.status_code == 200:
            # đơn giản lấy id exploit đầu tiên
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("table", {"id":"exploits-table"})
            if table:
                first = table.find("tbody").find("tr")
                if first:
                    exploit_id = first.get("data-id")
                    title = first.find("td", {"class":"description"}).text.strip()
                    return exploit_id, title
    except Exception as e:
        print("[!] Exploit-DB search error:", e)
    return None, None

def download_exploitdb_code(exploit_id):
    if not exploit_id:
        return None
    try:
        url = f"https://www.exploit-db.com/download/{exploit_id}"
        r = requests.get(url)
        if r.status_code == 200:
            fname = f"exploit_{exploit_id}"
            ext = r.headers.get('Content-Disposition')
            if ext and "." in ext:
                ext = ext.split('.')[-1].replace('"','').strip()
                fname += "." + ext
            else:
                fname += ".txt"
            with open(fname, "wb") as f:
                f.write(r.content)
            print(f"[i] Exploit code saved: {fname}")
            return fname
    except Exception as e:
        print("[!] Download exploit-db code error:", e)
    return None

# ------------- GitHub search exploit fallback -------------
def github_search_exploit(cve_id):
    if not CONFIG["github_token"]:
        return None, None
    from github import Github
    g = Github(CONFIG["github_token"])
    try:
        query = f"{cve_id} exploit"
        result = g.search_code(query, order="desc")
        for file in result:
            if file.download_url and any(file.download_url.endswith(x) for x in [".py", ".sh", ".pl", ".php", ".rb", ".js"]):
                return file.download_url, file.html_url
    except Exception as e:
        print("[!] GitHub search error:", e)
    return None, None

def download_github_code(url):
    try:
        r = requests.get(url)
        if r.status_code == 200:
            fname = url.split("/")[-1]
            with open(fname, "wb") as f:
                f.write(r.content)
            print(f"[i] GitHub exploit downloaded: {fname}")
            return fname
    except Exception as e:
        print("[!] Download GitHub code error:", e)
    return None

# ------------- Execute exploit -------------
def execute_exploit(filename, target):
    print(f"[i] Running exploit {filename} on target {target}")
    return run_in_docker(filename, target)

# ------------- Save logs -------------
def save_log():
    with open(CONFIG["log_file"], "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)
    print(f"[i] Log saved to {CONFIG['log_file']}")

def save_html_report():
    html = """
<html><head><title>Exploit Scan Report</title>
<style>body{font-family:Arial; margin:20px;} table{border-collapse: collapse; width: 100%;} th, td{border:1px solid #ddd; padding:8px;} th{background:#f2f2f2;}</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head><body><h1>Exploit Scan Report</h1>
"""
    html += f"<p>Report generated at: {datetime.now()}</p>"
    html += "<table><thead><tr><th>CVE ID</th><th>OS</th><th>Source</th><th>Target</th><th>Status</th></tr></thead><tbody>"
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
    </script></body></html>
    """ % (success, fail, max(0, len(log_data) - success - fail))

    with open("exploit_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[i] HTML report saved as exploit_report.html")

# ------------- Main Exploit CVE flow -------------
def exploit_cve(cve_id):
    print(f"\n=== Processing {cve_id} ===")

    # Download NVD bulk if missing
    if not os.path.isfile("nvd_data.json"):
        if not download_nvd_bulk():
            print("[!] Cannot proceed without NVD data")
            return

    desc = parse_nvd_cve_description("nvd_data.json", cve_id)
    os_detected = detect_os_from_description(desc)
    print(f"[i] Detected OS: {os_detected}")
    print(f"[i] Description: {desc[:150]}...")

    # Search exploit-db
    exploit_id, title = search_exploitdb(cve_id)
    source = "Exploit-DB"
    filename = None
    if exploit_id:
        filename = download_exploitdb_code(exploit_id)
    else:
        # fallback github
        print("[i] Searching on GitHub...")
        dl_url, gh_url = github_search_exploit(cve_id)
        source = "GitHub"
        if dl_url:
            filename = download_github_code(dl_url)

    if not filename:
        print(f"[-] No exploit found for {cve_id}")
        log_data.append({"cve": cve_id, "os": os_detected, "source": "None", "target": "N/A", "status": "fail"})
        return

    for target in CONFIG["targets"]:
        output = execute_exploit(filename, target)
        status = "success" if output.strip() else "fail"
        log_data.append({
            "cve": cve_id,
            "os": os_detected,
            "source": source,
            "target": target,
            "status": status,
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

# ------------- Flask Web UI -------------
app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Exploit Scan Dashboard</title>
<style>
body { font-family: Arial; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background: #f2f2f2; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<h1>Exploit Scan Dashboard</h1>

<button onclick="startScan()">Start Sample Scan</button>
<p id="status"></p>

<table>
<thead><tr><th>CVE</th><th>OS</th><th>Source</th><th>Target</th><th>Status</th></tr></thead>
<tbody id="logTable">
{% for e in log %}
<tr>
<td>{{e.cve}}</td><td>{{e.os}}</td><td>{{e.source}}</td><td>{{e.target}}</td><td>{{e.status}}</td>
</tr>
{% endfor %}
</tbody>
</table>

<canvas id="resultChart" width="400" height="200"></canvas>

<script>
function startScan(){
    document.getElementById('status').innerText = "Scanning...";
    fetch("/start_scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({cves: ["CVE-2021-44228", "CVE-2017-0144"] })
    }).then(res => res.json()).then(data => {
        document.getElementById('status').innerText = "Scan started!";
        setTimeout(() => location.reload(), 15000);
    });
}

const ctx = document.getElementById('resultChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'pie',
    data: {
        labels: ['Success', 'Fail', 'Unknown'],
        datasets: [{
            label: 'Exploit Results',
            data: [
                {{ log|selectattr("status", "equalto", "success")|list|length }},
                {{ log|selectattr("status", "equalto", "fail")|list|length }},
                {{ log|length - (log|selectattr("status", "equalto", "success")|list|length + log|selectattr("status", "equalto", "fail")|list|length) }}
            ],
            backgroundColor: ['#4caf50', '#f44336', '#9e9e9e']
        }]
    }
});
</script>
</body>
</html>
"""

@app.route('/')
def index():
    global log_data
    return render_template_string(HTML_TEMPLATE, log=log_data)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    cves = data.get("cves", [])
    threading.Thread(target=scan_cve_list, args=(cves,)).start()
    return jsonify({"status": "started"})

# ------------- Main -------------
if __name__ == "__main__":
    print("[i] Starting Exploit Scanner Web UI on http://127.0.0.1:5000")
    app.run(debug=False)
