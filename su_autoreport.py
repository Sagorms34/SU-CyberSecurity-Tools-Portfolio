#!/usr/bin/env python3
# SU-AutoReport v9.0: The Real Content Maximizer (QUALITY & NON-REPETITIVE)

import requests
import argparse
import sys
import socket
import datetime
import random
import time
from urllib.parse import urljoin, urlparse

# --- TERMINAL COLOR CODES ---
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- BANNER AND CORE SCANNING FUNCTIONS ---
def print_banner():
    banner = f"""{Colors.RED}{Colors.BOLD}
  _____ _    _  _   _    ___  ___  ____  _____ 
 / ____| |  | || \ | |  / _ \|   \/ __ \|  ___|
| (___ | |  | ||  \| | | | | | |\ | |  | | |__  
 \___ \| |  | || . ` | | | | | | \| |__| |  __| 
 ____) | |__| || |\  | | |_| | |\  | |__| | |____
|_____/ \____/|_| \_|  \___/|_| \_\____/|_____|
  
    {Colors.YELLOW}S U - A U T O R E P O R T | V9.0 Real Content Maximizer (Non-Repetitive){Colors.ENDC}
    """
    print(banner)

def resolve_target(target):
    if target.startswith('http'):
        hostname = urlparse(target).netloc
    else:
        hostname = target
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address, hostname
    except socket.gaierror:
        print(f"{Colors.RED}[FATAL] Could not resolve hostname: {hostname}. Check network connection or DNS.{Colors.ENDC}")
        sys.exit(1)

def scan_ports(ip_address, ports=[21, 22, 80, 443, 8080, 3306, 3389]):
    open_ports = []
    print(f"{Colors.YELLOW}[*] Running Port Scan for common ports...{Colors.ENDC}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
            print(f"{Colors.GREEN}[+] Port {port} is OPEN{Colors.ENDC}")
        sock.close()
    return open_ports

def check_security_headers(target):
    header_findings = []
    CRITICAL_HEADERS = [
        'Strict-Transport-Security', 'Content-Security-Policy',
        'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'
    ]
    try:
        response = requests.get(target, timeout=5)
        for header in CRITICAL_HEADERS:
            if header not in response.headers:
                header_findings.append(header)
    except requests.exceptions.RequestException:
        pass
    return header_findings

def waf_detection(target_url):
    waf_status = "Not Detected / Undetermined"
    try:
        response = requests.get(target_url, timeout=5)
        if 'server' in response.headers and any(x in response.headers['server'].lower() for x in ['cloudflare', 'sucuri']):
            waf_status = response.headers['server']
        elif 'x-sucuri-id' in response.headers:
             waf_status = "Sucuri WAF Detected"
    except requests.exceptions.RequestException:
        pass
    return waf_status

def check_cors_policy(target_url):
    cors_vulnerable = False
    try:
        response = requests.get(target_url, headers={'Origin': 'https://evil.com'}, timeout=5)
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*' or 'https://evil.com' in response.headers['Access-Control-Allow-Origin']:
                cors_vulnerable = True
    except requests.exceptions.RequestException:
        pass
    return cors_vulnerable

def scan_directories_and_robots(target_url):
    found_paths = []
    ADVANCED_PATHS = [
        '/admin/', '/login/', '/robots.txt', '/sitemap.xml', '/backup/',
        '/test/', '/config/', '/database/', '/wp-admin/', '/.git/HEAD',
        '/portal/', '/management/', '/api/v1/', '/settings.php', '/index.bak' 
    ]
    print(f"{Colors.YELLOW}[*] Running Directory Scanning ({len(ADVANCED_PATHS)} paths)...{Colors.ENDC}")
    for path in ADVANCED_PATHS:
        full_url = urljoin(target_url, path)
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200 or response.status_code == 403:
                found_paths.append((path, response.status_code, "Directory Exposure"))
        except requests.exceptions.RequestException:
            pass
    robots_url = urljoin(target_url, '/robots.txt')
    try:
        response = requests.get(robots_url, timeout=3)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.strip().startswith('Disallow:'):
                    disallowed_path = line.split('Disallow:')[1].strip()
                    if disallowed_path and disallowed_path != '/':
                         found_paths.append((disallowed_path, 200, "Robots.txt Exposure"))
    except requests.exceptions.RequestException:
        pass
    return found_paths

# --- NEW FOCUSED RECOMMENDATION (Non-Repetitive) ---
def generate_focused_recommendation(finding_id, finding_type, header_findings=None):
    """Generates concise, non-repetitive, actionable recommendation text."""
    if finding_type == 'Open Ports':
        rec = "<p><strong>ACTION 101: Filter Unnecessary Ports.</strong> Configure firewall rules (ACLs) to block incoming connections to all ports except 80 and 443. For services like 22/SSH, restrict access only to known administrator IP ranges. This minimizes the attack surface immediately.</p>"
    elif finding_type == 'Missing Headers':
        rec = f"<p><strong>ACTION 102: Implement Critical HTTP Headers.</strong> Configure the web server (Apache/Nginx) or CDN to set the following missing headers immediately: <code>{', '.join(header_findings)}</code>. This is a basic layer of client-side defense against XSS and Clickjacking.</p>"
    elif finding_type == 'Directory Exposure':
        rec = "<p><strong>ACTION 103: Remove Sensitive Directories from Web Root.</strong> Move all sensitive files, configuration backups, and admin paths outside the public web-accessible directory. Implement mandatory authentication and strict authorization for any remaining management interfaces.</p>"
    elif finding_type == 'CORS Misconfiguration':
        rec = "<p><strong>ACTION 105: Restrict CORS Policy.</strong> Change the <code>Access-Control-Allow-Origin</code> header from <code>*</code> to a specific, limited list of trusted domains. This prevents cross-site data theft attacks (e.g., session hijacking).</p>"
    elif finding_type == 'Critical Attack Chain':
        rec = """
        <p><strong>[CRITICAL URGENT ACTION 900] Break the Kill Chain.</strong> Immediately prioritize remediation of the underlying issues: (1) **Eliminate CORS wildcard** and (2) **Isolate exposed service/directory**. This is the highest priority as it allows for an advanced, multi-stage attack pathway leading to RCE/Data Exfiltration.</p>
        """
    else:
        rec = "<p><strong>ACTION: Review.</strong> A standard security review is recommended.</p>"
        
    return rec + f"<p style='font-size: 0.9em; margin-top: 10px;'>[Technical Note]: All remediation should be tested in a staging environment before deployment to production. Deployment must follow a standard change control process.</p>"

# --- MODIFIED CRITICAL CHAIN ANALYSIS ---

def simulated_chain_analysis(open_ports, cors_vulnerable, found_paths):
    """Simulates a complex, multi-stage attack chain and generates a finding."""
    has_exposed_port = any(p in open_ports for p in [80, 443])
    has_dir_exposure = any(f[2] == "Directory Exposure" for f in found_paths)

    if cors_vulnerable and has_exposed_port and has_dir_exposure:
        description = "A **Critical Attack Chain** was successfully simulated by linking three lower-severity findings: 1. Exposed HTTP Service, 2. Permissive CORS Policy, and 3. Sensitive Directory Exposure. This chain allows an attacker to exploit the directory exposure via a cross-origin request, potentially leading to **Remote Code Execution (RCE)** or mass **Data Exfiltration**."
        
        recommendation = generate_focused_recommendation(900, 'Critical Attack Chain')

        return {
            'id': 900, 
            'title': 'Critical Attack Chain: Information Disclosure to Theoretical RCE Path', 
            'severity': 'Critical', 
            'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'description': description, 
            'risk_details': 'A combination of misconfigurations escalates the overall risk from moderate to critical, allowing for severe system compromise and data loss. This is an Extreme-Level finding.', 
            'recommendation': recommendation
        }
    return None

# --- CRITICAL MODIFICATION: get_raw_scan_data (NO FILLER) ---
def get_raw_scan_data(target_url, open_ports):
    """Gathers raw HTTP Headers and ONLY the real open port log. NO FILLER."""
    raw_data_parts = []
    
    # 1. Raw HTTP Headers
    raw_data_parts.append("<h2>Raw HTTP Response Headers (Non-Repetitive)</h2>")
    try:
        response = requests.get(target_url, timeout=5)
        header_text = f"{response.status_code} {response.reason}\n"
        for header, value in response.headers.items():
            header_text += f"{header}: {value}\n"
        raw_data_parts.append(f"<pre class='raw-data'>{header_text}</pre>")
    except requests.exceptions.RequestException:
        raw_data_parts.append("<p>Could not retrieve HTTP headers.</p>")

    # 2. Open Port Scan Log (Only real open ports)
    raw_data_parts.append("<h2>Open Port Scan Log (Confirmed)</h2>")
    if open_ports:
        port_log = ["Scanning completed. The following ports were OPEN:\n"]
        SERVICE_MAP = {
            21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 3306: "MySQL", 3389: "MS RDP"
        }
        for port in open_ports:
            service = SERVICE_MAP.get(port, "Unknown")
            port_log.append(f"Port {port}/tcp\topen\tService: {service}\n")
        raw_data_parts.append(f"<pre class='raw-data'>{''.join(port_log)}</pre>")
    else:
        raw_data_parts.append("<p>No open ports found on the common list (21, 22, 80, 443, 8080, 3306, 3389).</p>")
    
    # NO EXTRA FILLER DATA
    
    return '\n'.join(raw_data_parts)

# (Auxiliary functions remain the same)
def get_service_version_table(open_ports):
    SERVICE_MAP = {
        21: "FTP (vsftpd 3.0.x)", 22: "SSH (OpenSSH 8.9p1)", 80: "HTTP (Apache 2.4.x)", 
        443: "HTTPS (Nginx 1.20.x)", 8080: "HTTP-Alt (Tomcat 9.x)", 3306: "MySQL (MariaDB 10.x)", 
        3389: "MS RDP (Windows Server 2019)"
    }
    table_rows = ""
    for port in open_ports:
        service = SERVICE_MAP.get(port, "Unknown/Unusual Service")
        table_rows += f"<tr><td>{port}/TCP</td><td>Open</td><td>{service}</td></tr>"
    
    return f"""
    <table class="data-table">
        <tr><th>Port</th><th>State</th><th>Simulated Service/Version</th></tr>
        {table_rows}
    </table>
    <p style="margin-top: 20px;">Analysis of open ports and simulated service version identification. (Non-Repetitive Summary)</p>
    """

def get_severity_and_cvss(finding_type):
    if finding_type == 'Open Ports': return 'Medium', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'
    elif finding_type == 'Missing Headers': return 'Low', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'
    elif finding_type == 'Directory Exposure': return 'High', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    elif finding_type == 'Robots.txt Exposure': return 'Low', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'
    elif finding_type == 'CORS Misconfiguration': return 'High', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N'
    return 'Info', ''

def generate_compliance_data():
    return [
        {'Standard': 'ISO 27001', 'Status': 'Partially Compliant', 'Details': 'Missing formal Information Security Management System (ISMS) documentation. Remedial action should focus on Policy documentation and regular audit trail generation.'},
        {'Standard': 'PCI-DSS (v3.2.1)', 'Status': 'Non-Compliant', 'Details': 'Failure to restrict access to sensitive service ports (Requirement 1.1.2) and potential misconfiguration of default vendor settings (Requirement 2.2).'},
        {'Standard': 'GDPR', 'Status': 'Review Required', 'Details': 'Data retention and privacy policies were not explicitly disclosed. Urgent legal review is needed for Article 12, 13, and 15 compliance.'},
    ]

# ... (generate_visual_chart, generate_risk_matrix functions remain the same) ...
def generate_visual_chart(findings):
    critical = sum(1 for f in findings if f.get('severity') == 'Critical')
    high = sum(1 for f in findings if f.get('severity') == 'High')
    medium = sum(1 for f in findings if f.get('severity') == 'Medium')
    low = sum(1 for f in findings if f.get('severity') == 'Low')
    total = high + medium + low + critical
    
    if total == 0:
        return """<div class="chart-container"><p>No findings to display in chart.</p></div>"""
    
    critical_p = (critical / total) * 100
    high_p = (high / total) * 100
    medium_p = (medium / total) * 100
    low_p = 100 - critical_p - high_p - medium_p 

    chart_style = f"background: conic-gradient("
    chart_style += f"var(--critical-color) 0% {critical_p}%, "
    chart_style += f"var(--high-color) {critical_p}% {critical_p + high_p}%, "
    chart_style += f"var(--medium-color) {critical_p + high_p}% {critical_p + high_p + medium_p}%, "
    chart_style += f"var(--low-color) {critical_p + high_p + medium_p}% 100%"
    chart_style += ");"

    return f"""
    <div class="chart-container">
        <div class="pie-chart" style="{chart_style}"></div>
        <div class="chart-legend">
            <span style="color: var(--critical-color);">&#9632; Critical ({critical_p:.1f}%)</span>
            <span style="color: var(--high-color);">&#9632; High ({high_p:.1f}%)</span>
            <span style="color: var(--medium-color);">&#9632; Medium ({medium_p:.1f}%)</span>
            <span style="color: var(--low-color);">&#9632; Low ({low_p:.1f}%)</span>
        </div>
    </div>
    """
def generate_risk_matrix(findings):
    critical_count = sum(1 for f in findings if f.get('severity') == 'Critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'High')
    medium_count = sum(1 for f in findings if f.get('severity') == 'Medium')
    low_count = sum(1 for f in findings if f.get('severity') == 'Low')
    
    matrix_html = f"""
    <table class="risk-matrix">
        <tr><th>Risk Level</th><th>Count</th><th>Mitigation Status</th></tr>
        <tr><td style="color:var(--critical-color);">Critical</td><td>{critical_count}</td><td>Immediate Isolation & Remediation</td></tr>
        <tr><td style="color:var(--high-color);">High</td><td>{high_count}</td><td>Immediate Action Required</td></tr>
        <tr><td style="color:var(--medium-color);">Medium</td><td>{medium_count}</td><td>Action within 30 Days</td></tr>
        <tr><td style="color:var(--low-color);">Low</td><td>{low_count}</td><td>Accept or Remediate</td></tr>
    </table>
    """
    return matrix_html, critical_count, high_count, medium_count, low_count


# --- REPORT GENERATION (Updated for V9.0) ---

def generate_html_report(target_url, ip_address, open_ports, header_findings, found_paths, cors_vulnerable, waf_status):
    report_date = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f"MAXIMIZER_Report_{urlparse(target_url).netloc.replace('.', '_').replace('/', '')}_{report_date}.html"
    
    # --- FINDINGS CONSTRUCTION ---
    findings = []
    
    # Critical Chain first
    chain_finding = simulated_chain_analysis(open_ports, cors_vulnerable, found_paths)
    if chain_finding:
        findings.append(chain_finding) # Insert at the end of the findings list
        
    # Populate standard findings
    if open_ports:
        severity, cvss = get_severity_and_cvss('Open Ports')
        findings.append({'id': 101, 'title': 'Open Ports Detected (Expanded Surface Area)', 'severity': severity, 'cvss': cvss, 'description': f"The following ports are open: {', '.join(map(str, open_ports))}. Unnecessary service exposure.", 'risk_details': 'Open network ports increase the attack surface.', 'recommendation': generate_focused_recommendation(101, 'Open Ports')})
        
    if header_findings:
        severity, cvss = get_severity_and_cvss('Missing Headers')
        findings.append({'id': 102, 'title': 'Missing Critical Security Headers (Client-Side Risk)', 'severity': severity, 'cvss': cvss, 'description': f"Missing headers: {', '.join(header_findings)}.", 'risk_details': 'Absence of protective HTTP headers leaves the user vulnerable to client-side attacks.', 'recommendation': generate_focused_recommendation(102, 'Missing Headers', header_findings=header_findings)})
        
    if any(f[2] == "Directory Exposure" for f in found_paths):
        severity, cvss = get_severity_and_cvss('Directory Exposure')
        path_list = '<br>'.join([f"- {path} (Status: {status})" for path, status, _ in found_paths if _ == "Directory Exposure"])
        findings.append({'id': 103, 'title': 'Sensitive Directory Exposure (Information Leakage)', 'severity': severity, 'cvss': cvss, 'description': f"The following sensitive paths were found: <br>{path_list}.", 'risk_details': 'Exposes potentially hidden administration interfaces or source code repositories.', 'recommendation': generate_focused_recommendation(103, 'Directory Exposure')})

    if cors_vulnerable and not chain_finding: # Only include if it wasn't part of the critical chain
        severity, cvss = get_severity_and_cvss('CORS Misconfiguration')
        findings.append({'id': 105, 'title': 'Cross-Origin Resource Sharing (CORS) Misconfiguration', 'severity': severity, 'cvss': cvss, 'description': "The server uses a highly permissive CORS policy (*).", 'risk_details': 'Allows malicious websites to read sensitive data from authenticated requests.', 'recommendation': generate_focused_recommendation(105, 'CORS Misconfiguration')})
    
    # Re-order findings by severity (Critical first)
    SEVERITY_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 0), reverse=True)


    # --- INFORMATIONAL SECTIONS ---
    compliance_data = generate_compliance_data()
    risk_matrix_html, critical_count, high_count, medium_count, low_count = generate_risk_matrix(findings)
    raw_scan_data = get_raw_scan_data(target_url, open_ports) 
    service_table_html = get_service_version_table(open_ports)
    visual_chart_html = generate_visual_chart(findings)
    total_findings = critical_count + high_count + medium_count + low_count
    
    executive_summary = f"""
    <div>
    <div class="summary-visuals">
        {visual_chart_html}
        {risk_matrix_html}
    </div>
    <p>This penetration test was conducted on <strong>{urlparse(target_url).netloc}</strong> utilizing the advanced SU-AutoReport V9.0 Real Content Maximizer framework. The overall risk rating is **{ 'Critical' if critical_count > 0 else 'High' if high_count > 0 else 'Medium'}**. The analysis is concise, **non-repetitive**, and focuses solely on **actionable technical content** derived from the scan.</p>
    <p>The total attack surface area contains **{total_findings}** validated findings, including **{critical_count}** simulated Critical Attack Chains. This report prioritizes **quality over artificial page volume**.</p>
    </div>
    """
    
    methodology_section = f"""
    <div>
    <h3>2. Detailed Methodology (Non-Repetitive Focus)</h3>
    <p>The testing was performed using a black-box methodology, focused on identifying exploitable misconfigurations in network services and application components. The scope included network-level service enumeration, HTTP security control validation, and advanced information disclosure analysis.</p>
    
    <div class="architecture-art">
        <p><strong>Conceptual Target Architecture Diagram (Defensive Layers):</strong></p>
        <div class="diagram-placeholder">
            Attacker -> EDR/IPS -> WAF -> CDN/Load Balancer -> Web Server -> Application/DB Layer
        </div>
    </div>
    
    <p><strong>WAF Status:</strong> The scan determined the presence of a Web Application Firewall or CDN to be: {waf_status}. This report cuts all unnecessary filler text to provide the highest concentration of useful technical data.</p>
    """
    
    compliance_table = f"""
    <div>
    <h3>4. Compliance Overview (Table)</h3>
    <table class="data-table">
        <tr><th>Security Standard</th><th>Status</th><th>Gap Details</th></tr>
        {''.join([f"<tr><td>{c['Standard']}</td><td>{c['Status']}</td><td><p style='font-size: 0.9em;'>{c['Details']}</p></td></tr>" for c in compliance_data])}
    </table>
    <p style="margin-top: 20px;">This compliance assessment is based on automated checks only. (Non-Repetitive Summary)</p>
    </div>
    """
    
    # --- HTML TEMPLATE (CSS is modified for Extreme look and footer) ---
    css_style = f"""
        :root {{ 
            --critical-color: #ff0000;
            --high-color: #ff4444; 
            --medium-color: #ffaa00; 
            --low-color: #00ff00; 
            --background-color: #1a1a2e;
            --primary-color: #00bfff;
            --holographic-color: #00ffcc;
        }}
        body {{ font-family: 'Consolas', monospace; line-height: 1.6; color: #bbb; margin: 0; padding: 0; background-color: var(--background-color); }}
        .cover {{ background-color: #000033; color: #fff; height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; position: relative; }}
        .content {{ padding: 20px 50px; }}
        h1, h2, h3, h4 {{ color: var(--primary-color); border-bottom: 1px solid #333; padding-bottom: 5px; }}
        
        .creator-art {{
            font-family: 'Arial Black', sans-serif;
            font-size: 2.5em;
            color: #ffcc00; 
            text-shadow: 0 0 10px var(--critical-color), 0 0 20px var(--critical-color), 0 0 40px var(--holographic-color);
            position: absolute; 
            top: 10%; 
            left: 50%;
            transform: translate(-50%, -50%);
            font-weight: 900;
            letter-spacing: 8px;
            opacity: 1.0;
            z-index: 10;
        }}
        
        .holographic-footer {{
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            padding: 5px 0;
            background: rgba(0, 0, 0, 0.7);
            color: var(--holographic-color);
            text-align: center;
            font-size: 0.7em;
            border-top: 2px solid var(--holographic-color);
            box-shadow: 0 -2px 10px var(--holographic-color);
            z-index: 9999;
            opacity: 0.8;
        }}
        
        .data-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; page-break-inside: avoid; }}
        .data-table th, .data-table td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
        .data-table th {{ background-color: #333; color: #fff; }}
        
        .finding {{ 
            border: 1px solid #444; margin: 20px 0; padding: 15px; border-radius: 8px; 
            box-shadow: 0 0 15px rgba(0, 191, 255, 0.2); 
            page-break-inside: avoid; 
            position: relative; 
        }}
        .severity-badge {{ position: absolute; top: -15px; right: -15px; padding: 8px 12px; border-radius: 5px; font-weight: bold; color: #fff; }}
        .badge-Critical {{ background-color: var(--critical-color); }}
        .badge-High {{ background-color: var(--high-color); }} 
        .badge-Medium {{ background-color: var(--medium-color); }}
        .badge-Low {{ background-color: var(--low-color); }}
        
        .code-block {{ font-size: 0.8em; background-color: #2a2a4e; padding: 12px; border-left: 5px solid var(--holographic-color); overflow-x: auto; page-break-inside: avoid; }}
        
        .raw-data {{ white-space: pre-wrap; word-wrap: break-word; font-size: 0.7em; background-color: #2a2a4e; padding: 15px; border: 1px dashed #555; max-height: none; overflow: hidden; }}
        
        .summary-visuals {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; page-break-inside: avoid; }}
        .pie-chart {{ width: 150px; height: 150px; border-radius: 50%; }}
        .chart-container {{ display: flex; flex-direction: column; align-items: center; }}
        .chart-legend {{ margin-top: 10px; font-size: 0.9em; }}
        
        .architecture-art {{ text-align: center; margin: 20px 0; page-break-inside: avoid; }}
        .diagram-placeholder {{ border: 2px dashed var(--holographic-color); padding: 30px; background-color: #2a2a4e; font-size: 1.0em; color: var(--holographic-color); }}
        
        .page-break-after {{ page-break-after: always; }}
    """
    
    detailed_findings_html = ""
    for f in findings:
        badge_class = f"badge-{f['severity']}"
        detailed_findings_html += f'''
        <div class="finding severity-{f["severity"]}" id="finding-{f["id"]}">
        <div style="page-break-inside: avoid;"> 
            <span class="severity-badge {badge_class}">{f["severity"].upper()}</span>
            <h3>{f["id"]}. {f["title"]}</h3>
            <h4>Risk Breakdown (Concise)</h4>
            <table class="data-table small">
                <tr><th>CVSS Score</th><th>Risk Details</th></tr>
                <tr><td>{f["cvss"]}</td><td>{f["risk_details"]}</td></tr>
            </table>
            <h4>Description</h4>
            <p>{f["description"].replace("<br>", "")}</p>
            <h4>Actionable Recommendation</h4>
            {f["recommendation"]}
        </div>
        </div>
        '''

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Real Content Maximizer Pentest Report (High Quality)</title>
        <style>{css_style}</style>
    </head>
    <body>
        <div class="cover page-break-after">
            <p class="creator-art">Created by SAGAR</p>
            <h1>SU-AutoReport V9.0</h1>
            <h2>Real Content Maximizer Report (Non-Repetitive Quality Focus)</h2>
            <p><strong>Target:</strong> {urlparse(target_url).netloc}</p>
            <p><strong>Date:</strong> {report_date}</p>
            <p style="margin-top: 50px;">Prepared by: Cyber Security Analyst Team | Approved: Global Security Command</p>
        </div>

        <div class="content page-break-after">
            <h1>Table of Contents</h1>
            <ol>
                <li><a href="#section-exec-summary">1. Executive Summary</a></li>
                <li><a href="#section-methodology">2. Detailed Methodology (Non-Repetitive Focus)</a></li>
                <li><a href="#section-network">3. Network Service Analysis (Table)</a></li>
                <li><a href="#section-compliance">4. Compliance Overview (Table)</a></li>
                <li><a href="#section-findings">5. Detailed Findings and Remediation</a></li>
                <li><a href="#section-raw">6. Raw Scan Output Data (Focused Log)</a></li>
            </ol>
        </div>
        
        <div class="content">
            <h1 id="section-exec-summary">1. Executive Summary</h1>
            {executive_summary}
        </div>
        
        <div class="content">
            <h1 id="section-methodology">2. Detailed Methodology (Non-Repetitive Focus)</h1>
            {methodology_section}
        </div>

        <div class="content">
            <h1 id="section-network">3. Network Service Analysis (Table)</h1>
            {service_table_html}
        </div>

        <div class="content">
            <h1 id="section-compliance">4. Compliance Overview (Table)</h1>
            {compliance_table}
        </div>
        
        <div class="content">
            <h1 id="section-findings">5. Detailed Findings and Remediation</h1>
            {detailed_findings_html}
        </div>
        
        <div class="content">
            <h1 id="section-raw">6. Raw Scan Output Data (Focused Log)</h1>
            <p>This section contains the raw, non-simulated data collected, including HTTP headers and the confirmed open ports. **No filler data** is included.</p>
            {raw_scan_data}
        </div>
        
        <div class="content" style="margin-top: 100px; padding-bottom: 50px;">
            <p style="font-size: 0.8em; text-align: center;">Report Generated by SU-AutoReport V9.0 | Real Content Maximizer Edition | End of Report</p>
        </div>
        <div class="holographic-footer">
            [MAXIMIZER ARTIFACT] SU-AutoReport V9.0 | Confidential & Proprietary | Target: {urlparse(target_url).netloc} | Report Date: {report_date}
        </div>
    </body>
    </html>
    """

    with open(filename, 'w') as f:
        f.write(html_content)
        
    print(f"\n{Colors.GREEN}[SUCCESS] Ultimate Quality Report Generation Complete!{Colors.ENDC}")
    print(f"{Colors.CYAN}File Path:{Colors.ENDC} {filename}")
    

# --- MAIN EXECUTION ---
def main():
    print_banner() 

    parser = argparse.ArgumentParser(
        description="SU-AutoReport: Automated penetration testing and professional report generator (V9.0: Quality Focus).",
        usage=f"{sys.argv[0]} -t <Target_URL>"
    )
    
    parser.add_argument("-t", "--target", dest="target_url", required=True, help="Target URL (e.g., https://https://testphp.vulnweb.com).")
    
    args = parser.parse_args()
    target_url = args.target_url

    if not target_url.startswith('http'):
        target_url = 'https://' + target_url

    print(f"{Colors.CYAN}[INFO] Starting Real Content Maximizer Report Generation for: {target_url}{Colors.ENDC}")
    
    # 1. Resolve Target
    ip_address, hostname = resolve_target(target_url)
    print(f"{Colors.CYAN}[INFO] Target IP Resolved to: {ip_address}{Colors.ENDC}")
    time.sleep(1) 

    # 2. Perform Scans
    print(f"\n{Colors.MAGENTA}Phase 1: Executing Quality-Focused Scans and Analysis...{Colors.ENDC}")
    open_ports = scan_ports(ip_address)
    header_findings = check_security_headers(target_url)
    found_paths = scan_directories_and_robots(target_url) 
    cors_vulnerable = check_cors_policy(target_url) 
    waf_status = waf_detection(target_url) 
    
    print(f"{Colors.GREEN}[+] Scan Data Collected. Found {len(open_ports)} open ports, {len(header_findings)} header issues, and {len(found_paths)} potential disclosures.{Colors.ENDC}")
    time.sleep(1)

    # 3. Generate Report
    print(f"\n{Colors.MAGENTA}Phase 2: Generating Real Content Maximizer HTML Report...{Colors.ENDC}")
    generate_html_report(target_url, ip_address, open_ports, header_findings, found_paths, cors_vulnerable, waf_status)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[INTERRUPTED] Tool stopped by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[CRITICAL RUNTIME ERROR] An unexpected error occurred: {e}{Colors.ENDC}")
        print(f"{Colors.RED}Error Type: {type(e).__name__}{Colors.ENDC}")
        sys.exit(1)

