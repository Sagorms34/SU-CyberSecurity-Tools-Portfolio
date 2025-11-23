
#!/usr/bin/env python3
# SU-AutoReport v4.0: Super Advanced Report Generator (Apex Edition)

import requests
import argparse
import sys
import socket
import datetime
import random
import time
import json
from urllib.parse import urljoin

# --- TERMINAL COLOR CODES ---
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- BANNER FUNCTION ---
def print_banner():
    """Prints the SU-AutoReport ASCII Art banner."""
    banner = f"""{Colors.RED}{Colors.BOLD}
  _____ _    _  _   _    ___  ___  ____  _____ 
 / ____| |  | || \ | |  / _ \|   \/ __ \|  ___|
| (___ | |  | ||  \| | | | | | |\ | |  | | |__  
 \___ \| |  | || . ` | | | | | | \| |  | |  __| 
 ____) | |__| || |\  | | |_| | |\ | |__| | |____
|_____/ \____/|_| \_|  \___/|_| \_\____/|_____|
  
    {Colors.YELLOW}S U - A U T O R E P O R T | Super Advanced Report v4.0 (Apex){Colors.ENDC}
    """
    print(banner)

# --- CORE SCANNING AND REPORTING FUNCTIONS ---

def resolve_target(target):
    """Resolves hostname to IP address."""
    if target.startswith('http'):
        hostname = target.split('//')[-1].split('/')[0]
    else:
        hostname = target
    
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address, hostname
    except socket.gaierror:
        print(f"{Colors.RED}[FATAL] Could not resolve hostname: {hostname}{Colors.ENDC}")
        sys.exit(1)

def scan_ports(ip_address, ports=[21, 22, 80, 443, 3389]):
    """Performs a basic port scan on common ports."""
    open_ports = []
    print(f"{Colors.YELLOW}[*] Running Port Scan for common ports...{Colors.ENDC}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
            print(f"{Colors.GREEN}[+] Port {port} is OPEN{Colors.ENDC}")
        sock.close()
    return open_ports

def check_security_headers(target):
    """Checks for critical HTTP Security Headers."""
    header_findings = []
    
    CRITICAL_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
    ]

    try:
        response = requests.get(target, timeout=5)
        
        for header in CRITICAL_HEADERS:
            if header not in response.headers:
                header_findings.append(header)
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[ERROR] Header check failed: {e}{Colors.ENDC}")

    return header_findings

# --- NEW ADVANCED SCANNING FUNCTION 1: DIRECTORY ENUMERATION ---
def scan_directories(target_url):
    """Checks for common sensitive directories (e.g., admin panels)."""
    found_paths = []
    
    # A small list of common directories for quick testing
    COMMON_PATHS = [
        '/admin/', 
        '/login/', 
        '/wp-login.php', 
        '/robots.txt',
        '/.git/HEAD' # Git exposure check
    ]
    
    print(f"{Colors.YELLOW}[*] Running Directory Scanning (5 common paths)...{Colors.ENDC}")
    
    for path in COMMON_PATHS:
        full_url = urljoin(target_url, path)
        try:
            response = requests.get(full_url, timeout=3)
            # 200 OK or 403 Forbidden suggests the path exists
            if response.status_code == 200 or response.status_code == 403:
                found_paths.append((path, response.status_code))
                print(f"{Colors.RED}[!] Found Path: {path} (Status: {response.status_code}){Colors.ENDC}")
            else:
                pass
        except requests.exceptions.RequestException:
            pass
            
    return found_paths

# --- NEW ADVANCED SCANNING FUNCTION 2: TECHNOLOGY IDENTIFICATION ---
def identify_technology(target_url):
    """Tries to identify underlying technologies from HTTP headers."""
    tech_info = {}
    
    try:
        response = requests.get(target_url, timeout=5)
        # Identify Server Type
        if 'Server' in response.headers:
            tech_info['Server'] = response.headers['Server']
        # Identify X-Powered-By (e.g., PHP, ASP.NET)
        if 'X-Powered-By' in response.headers:
            tech_info['Powered-By'] = response.headers['X-Powered-By']
            
    except requests.exceptions.RequestException:
        pass
        
    return tech_info
    
# --- REPORT GENERATION AND SCORING ---

def get_severity_and_cvss(finding_type):
    """Assigns severity and a base CVSS score for the report."""
    if finding_type == 'Open Ports':
        return 'Medium', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'
    elif finding_type == 'Missing Headers':
        return 'Low', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'
    elif finding_type == 'Directory Exposure':
        return 'High', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    return 'Info', ''


def generate_html_report(target_url, ip_address, open_ports, header_findings, found_paths, tech_info):
    """Generates a professional HTML report (Apex Edition)."""
    report_date = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f"APEX_Pentest_Report_{target_url.split('//')[-1].replace('.', '_').replace('/', '')}_{report_date}.html"
    
    # --- FINDINGS CONSTRUCTION ---
    findings = []
    
    # 1. Open Ports Finding
    if open_ports:
        severity, cvss = get_severity_and_cvss('Open Ports')
        findings.append({
            'title': 'Open Ports Detected',
            'severity': severity,
            'cvss': cvss,
            'description': f"The following ports are open: {', '.join(map(str, open_ports))}. This significantly increases the attack surface.",
            'recommendation': 'Restrict access to these ports via firewall rules (ACLs) to trusted IP ranges only.'
        })
        
    # 2. Missing Headers Finding
    if header_findings:
        severity, cvss = get_severity_and_cvss('Missing Headers')
        findings.append({
            'title': 'Missing Critical Security Headers',
            'severity': severity,
            'cvss': cvss,
            'description': f"The application is missing critical security headers: {', '.join(header_findings)}. This leaves the user vulnerable to XSS and Clickjacking attacks.",
            'recommendation': 'Implement all critical HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) to mitigate common web vulnerabilities.'
        })
        
    # 3. Directory Exposure Finding (NEW)
    if found_paths:
        severity, cvss = get_severity_and_cvss('Directory Exposure')
        path_list = '<br>'.join([f"- {path} (Status: {status})" for path, status in found_paths])
        findings.append({
            'title': 'Sensitive Directory Exposure',
            'severity': severity,
            'cvss': cvss,
            'description': f"The following sensitive or common application paths were found: <br>{path_list}. This exposes potentially hidden administration interfaces or source code.",
            'recommendation': 'Block access to sensitive paths (like admin dashboards and configuration files) using web server configuration (e.g., .htaccess or NGINX location blocks).'
        })

    # --- INFORMATIONAL SECTION (NEW) ---
    info_section = ""
    if tech_info:
        tech_list = ''.join([f"<li><strong>{k}:</strong> {v}</li>" for k, v in tech_info.items()])
        info_section = f"""
        <h3>2. Technology Information</h3>
        <p>The following technologies were identified from the HTTP response headers:</p>
        <ul>{tech_list}</ul>
        """

    # --- HTML Template ---
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Apex Pentest Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 20px; }}
            .header {{ background-color: #333; color: white; padding: 20px; text-align: center; }}
            .finding {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }}
            .severity-High {{ border-left: 5px solid red; background-color: #ffe0e0; }}
            .severity-Medium {{ border-left: 5px solid orange; background-color: #fff4e0; }}
            .severity-Low {{ border-left: 5px solid yellowgreen; background-color: #f0fff0; }}
            .cvss {{ font-size: 0.9em; color: #555; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SU-AutoReport V4.0 - Apex Penetration Test Report</h1>
            <p>Target: {target_url} (IP: {ip_address}) | Date: {report_date}</p>
        </div>
        
        {info_section}
        
        <h2>3. Detailed Findings</h2>
        {''.join([
            f'''<div class="finding severity-{f["severity"]}">
                <h3>{f["title"]} ({f["severity"]})</h3>
                <p class="cvss"><strong>CVSS Vector:</strong> {f["cvss"]}</p>
                <p><strong>Description:</strong> {f["description"]}</p>
                <p><strong>Recommendation:</strong> {f["recommendation"]}</p>
            </div>'''
            for f in findings
        ])}
        <p style="text-align: center; margin-top: 30px;">Report Generated by SU-AutoReport v4.0</p>
    </body>
    </html>
    """

    with open(filename, 'w') as f:
        f.write(html_content)
        
    print(f"\n{Colors.GREEN}[SUCCESS] Report Generation Complete!{Colors.ENDC}")
    print(f"{Colors.CYAN}File Path:{Colors.ENDC} {filename}")
    
# --- MAIN EXECUTION ---

def main():
    print_banner() 

    parser = argparse.ArgumentParser(
        description="SU-AutoReport: Automated penetration testing and professional report generator.",
        usage=f"{sys.argv[0]} -t <Target_URL>"
    )
    
    parser.add_argument("-t", "--target", dest="target_url", required=True, help="Target URL (e.g., https://example.com).")
    
    args = parser.parse_args()
    target_url = args.target_url

    if not target_url.startswith('http'):
        target_url = 'http://' + target_url

    print(f"{Colors.CYAN}[INFO] Starting Super Advanced Report Generation for: {target_url}{Colors.ENDC}")
    
    # 1. Resolve Target
    ip_address, hostname = resolve_target(target_url)
    print(f"{Colors.CYAN}[INFO] Target IP Resolved to: {ip_address}{Colors.ENDC}")
    time.sleep(1) 

    # 2. Perform Scans
    print(f"\n{Colors.MAGENTA}Phase 1: Executing Real-Time Multi-Vector Scans...{Colors.ENDC}")
    open_ports = scan_ports(ip_address)
    header_findings = check_security_headers(target_url)
    found_paths = scan_directories(target_url) # NEW SCAN
    tech_info = identify_technology(target_url) # NEW SCAN
    
    print(f"{Colors.GREEN}[+] Scan Data Collected. Found {len(open_ports)} open ports, {len(header_findings)} header issues, and {len(found_paths)} exposed directories.{Colors.ENDC}")
    time.sleep(1)

    # 3. Generate Report
    print(f"\n{Colors.MAGENTA}Phase 2: Generating Professional HTML Report...{Colors.ENDC}")
    generate_html_report(target_url, ip_address, open_ports, header_findings, found_paths, tech_info)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[INTERRUPTED] Tool stopped by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[CRITICAL ERROR] An unexpected error occurred: {e}{Colors.ENDC}")
        sys.exit(1)

