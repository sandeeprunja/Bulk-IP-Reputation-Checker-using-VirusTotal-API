# 🛡️ Bulk IP Reputation Checker using VirusTotal API

This script checks the reputation of IP addresses using the VirusTotal API and exports the results into an Excel file with detailed analysis.

## 🔧 Features
- Retrieves IP reputation: malicious, suspicious, harmless, undetected.
- Fetches country, ASN, network, and DNS resolutions.
- Saves output to an Excel report (`.xlsx`).
- Supports batch processing from `ips.txt`.

## 📂 Files
- `ip_reputation_checker.py`: Main script
- `ips.txt`: Input file with list of IPs (one per line)
- `ip_reputation_detailed.xlsx`: Output Excel file (generated)

## 🚀 Usage

```bash
pip install openpyxl requests
python ip_reputation_checker.py

import requests
import time
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font

# === CONFIGURATION ===
API_KEY = 'XXXX'  # Replace this with your actual API key
INPUT_FILE = 'ips.txt'
OUTPUT_FILE = 'ip_reputation_detailed.xlsx'
RATE_LIMIT_SLEEP = 15  # Free tier

headers = {
    "x-apikey": API_KEY
}

# === READ IPs ===
try:
    with open(INPUT_FILE, 'r') as file:
        ip_list = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"❌ Input file '{INPUT_FILE}' not found.")
    exit()

# === CREATE EXCEL WORKBOOK ===
wb = Workbook()
ws = wb.active
ws.title = "IP Reputation Report"

# Header Row
headers_row = [
    "IP", "Country", "ASN", "Network", "Malicious", 
    "Suspicious", "Harmless", "Undetected", 
    "Tags", "Last Analysis Date", "Malicious DNS"
]
ws.append(headers_row)

# Bold header
for cell in ws[1]:
    cell.font = Font(bold=True)

# === PROCESS EACH IP ===
for ip in ip_list:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']
            tags = attributes.get('tags', [])
            country = attributes.get('country', 'N/A')
            network = attributes.get('network', 'N/A')
            asn = attributes.get('asn', 'N/A')
            last_analysis_ts = attributes.get('last_analysis_date', 0)
            last_analysis = datetime.utcfromtimestamp(last_analysis_ts).strftime('%Y-%m-%d %H:%M:%S')

            # DNS resolutions
            dns_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
            dns_response = requests.get(dns_url, headers=headers)
            malicious_dns = []
            if dns_response.status_code == 200:
                dns_data = dns_response.json()
                for item in dns_data.get('data', []):
                    hostname = item.get('attributes', {}).get('hostname')
                    if hostname:
                        malicious_dns.append(hostname)

            ws.append([
                ip,
                country,
                asn,
                network,
                stats.get('malicious', 0),
                stats.get('suspicious', 0),
                stats.get('harmless', 0),
                stats.get('undetected', 0),
                ', '.join(tags),
                last_analysis,
                ', '.join(malicious_dns[:5])  # Limit DNS entries
            ])
            print(f"[+] Processed: {ip}")

        else:
            print(f"[!] API Error for {ip}: {response.status_code}")
            ws.append([ip] + ['Error'] * (len(headers_row) - 1))

    except Exception as e:
        print(f"[!] Exception for {ip}: {e}")
        ws.append([ip] + ['Error'] * (len(headers_row) - 1))

    time.sleep(RATE_LIMIT_SLEEP)

# === SAVE EXCEL FILE ===
wb.save(OUTPUT_FILE)
print(f"\n✅ Excel report saved as '{OUTPUT_FILE}'")
