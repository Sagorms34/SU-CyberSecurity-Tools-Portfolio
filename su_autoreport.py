
#!/usr/bin/env python3
# SU-AutoReport: APEX Penetration Testing Report Generator (HTML Output v4.0)

import argparse
import sys
import os
import requests
import time
import socket
from urllib.parse import urlparse

# --- TERMINAL COLOR CODES ---
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- BANNER FUNCTION ---
def print_banner():
    """Prints the SU-AutoReport ASCII Art banner."""
    banner = f"""{Colors.CYAN}
   _____ __ __  _______  ____  _______    ___ ____  
  / ___/|  |  |/  _____/|    |/  _____/   |   |    \ 
 (   \_ |  |  |   \___  |  o  |   \___    |   |  D  )
  \____||__|__| \______/|____|\______/   |___|____/ 
  
    {Colors.YELLOW}{Colors.BOLD}S U - A U T O R E P O R T | APEX HTML Report v4.0{Colors.ENDC}
    """
    print(banner)

# --- ADVANCED SCANNING AND ANALYSIS MODULES ---

def get_service_banner(host, port):
    """Attempts to grab a service banner (e.g., HTTP Server header or SSH version)."""
    try:
        if port in [80, 443]:
            # For HTTP/HTTPS, grab Server header
            target_url = f"http{'s' if port == 443 else ''}://{host}:{port}"
            response = requests.head(target_url, timeout=1.5, allow_redirects=True)
            return response.headers.get('Server', 'Header not disclosed'), response.headers
        else:
            # For other ports (SSH, FTP), attempt a simple banner grab
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect((host, port))
            if port in [21, 22]:
                data = sock.recv(1024).decode(errors='ignore').strip().split('\n')[0]
                sock.close()
                return data, {}
    except Exception:
        return "Banner grab failed/Service timeout", {}
    return "N/A", {}

def analyze_robots_txt(target_url):
    """Analyzes robots.txt for disallowed sensitive paths."""
    print(f"  {Colors.CYAN}[SCAN] Analyzing robots.txt for disallowed paths...{Colors.ENDC}")
    robots_url = target_url.rstrip('/') + '/robots.txt'
    disallowed_paths = []
    
    try:
        response = requests.get(robots_url, timeout=3)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if line.strip().lower().startswith('disallow:'):
                    path = line.split(':')[1].strip()
                    if path and path not in ['/', '/ ']:
                        disallowed_paths.append(path)
        
    except requests.exceptions.RequestException:
        pass
            
    return disallowed_paths

def analyze_security_headers(headers):
    """Checks for the presence of critical HTTP Security Headers."""
    missing_headers = []
    
    required_headers = {
        'Strict-Transport-Security': 'HSTS prevents downgrade attacks. HIGH risk if site uses HTTPS.',
        'Content-Security-Policy': 'CSP prevents XSS and data injection attacks. HIGH risk.',
        'X-Content-Type-Options': 'Prevents MIME sniffing attacks. MEDIUM risk.',
        'Permissions-Policy': 'Controls browser features usage (e.g., camera, mic). LOW risk.'
    }
    
    for header, description in required_headers.items():
        if header not in headers:
            missing_headers.append({"header": header, "description": description})
            
    return missing_headers

def calculate_severity_and_cvss(title, context_data):
    """Dynamically calculates the Severity, CVSS Score, and Vector."""
    title = title.lower()
    severity = "Medium"
    cvss = "5.0"
    vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" # Base Medium
    
    # --- HIGH Severity Conditions ---
    if "exposed directory: /admin" in title or "sensitive config file" in title:
        severity = "High"
        cvss = "9.8" 
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Critical Risk
    
    if "missing: strict-transport-security" in title:
        severity = "High"
        cvss = "7.5"
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
        
    if "missing: content-security-policy" in title:
        severity = "High"
        cvss = "8.8"
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    
    # --- MEDIUM Severity Conditions ---
    elif "weak ssl/tls protocol (tls 1.0/1.1)" in title:
        severity = "Medium"
        cvss = "6.5"
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        
    elif "open port 22 (ssh)" in title:
        if "openssh 7" in context_data.get('banner', '').lower() or "openssh 8.2" in context_data.get('banner', '').lower():
            severity = "High" # Elevated due to potential old version
            cvss = "7.5"
            vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        else:
            severity = "Medium"
            cvss = "5.3"
            
    elif "missing x-frame-options header" in title or "missing: x-content-type-options" in title:
        severity = "Medium"
        cvss = "6.1"
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" # Clickjacking/MIME Sniffing

    # --- LOW Severity Conditions ---
    elif "open port" in title or "disallowed path exposed" in title or "missing: permissions-policy" in title:
        severity = "Low"
        cvss = "3.5"
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    return severity, cvss, vector

def scan_ports(host):
    """Real-Time Port Scanning for common services with Banner Grabbing."""
    print(f"  {Colors.CYAN}[SCAN] Running Port Scan and Banner Grabbing...{Colors.ENDC}")
    open_ports = []
    ports_to_check = [21, 22, 80, 443, 3389]
    
    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = 'Unknown'
            
            banner, headers = get_service_banner(host, port)
            open_ports.append({"port": port, "service": service, "banner": banner, "headers": headers})
        sock.close()
    
    return open_ports

def scan_directories(target_url):
    """Real-Time Directory Enumeration for sensitive paths."""
    print(f"  {Colors.CYAN}[SCAN] Running Directory Enumeration for sensitive paths...{Colors.ENDC}")
    sensitive_paths = ["admin/", "login/", "config/", ".env", "phpinfo.php", "backup.zip"]
    found_dirs = []
    
    for path in sensitive_paths:
        url_to_check = target_url.rstrip('/') + '/' + path
        try:
            response = requests.get(url_to_check, timeout=1.5, allow_redirects=True)
            if response.status_code in [200, 301, 302] and response.status_code != 404:
                found_dirs.append({"path": path, "status": response.status_code})
                if path.endswith('.env') and 'APP_KEY' in response.text:
                    found_dirs[-1]['sensitive'] = True
            
        except requests.exceptions.RequestException:
            pass
            
    return found_dirs
    
def get_realtime_findings(target_url):
    """Runs all real-time scans and aggregates findings."""
    print(f"{Colors.YELLOW}[*] Phase 1: Executing Real-Time Multi-Vector Scans...{Colors.ENDC}")
    
    parsed_url = urlparse(target_url)
    host = parsed_url.netloc.split(':')[0]
    
    try:
        ip_address = socket.gethostbyname(host)
        print(f"  {Colors.CYAN}[INFO] Target IP Resolved to: {ip_address}{Colors.ENDC}")
    except socket.gaierror:
        return {"Target_Scope": target_url, "Findings": [], "Host_IP": "N/A", "Summary": "Target host could not be resolved."}
    
    # Data Collection
    open_ports = scan_ports(ip_address)
    found_dirs = scan_directories(target_url)
    disallowed_paths = analyze_robots_txt(target_url)
    
    final_findings = []
    
    # --- Port Scan & Banner Findings ---
    for port_info in open_ports:
        title = f"Open Port {port_info['port']} ({port_info['service']})"
        banner_info = port_info['banner']
        
        severity, cvss, vector = calculate_severity_and_cvss(title, {"banner": banner_info})
        
        final_findings.append({
            "Title": title,
            "Severity": severity,
            "CVSS": cvss,
            "Vector": vector,
            "VULN_TYPE": "Service Exposure/Information Disclosure",
            "AFFECTED_ASSET": f"IP: {ip_address}, Port: {port_info['port']}",
            "Description": f"Port {port_info['port']} was found open on the target server. Service Banner: {banner_info}.",
            "PoC": f"Successful connection established to {ip_address}:{port_info['port']}. Banner data was extracted.",
            "Recommendation": "Implement strict firewall rules (ACLs) to restrict access to services to trusted IP ranges only. Ensure all exposed services are running the latest patched versions to prevent exploitation."
        })
        
        # --- Check for Weak TLS (Simulated) ---
        if port_info['port'] == 443:
            # Simple simulation: assume all external services must support TLS 1.2+
            if 'cloudflare' not in banner_info.lower() and ip_address != '127.0.0.1':
                tls_title = "Weak SSL/TLS Protocol (TLS 1.0/1.1 Simulated)"
                severity, cvss, vector = calculate_severity_and_cvss(tls_title, {})
                final_findings.append({
                    "Title": tls_title,
                    "Severity": severity,
                    "CVSS": cvss,
                    "Vector": vector,
                    "VULN_TYPE": "Insecure Configuration",
                    "AFFECTED_ASSET": f"IP: {ip_address}, Port: 443",
                    "Description": "The server appears to support older, insecure SSL/TLS protocols (simulated). These protocols are susceptible to known attacks (e.g., POODLE, BEAST).",
                    "PoC": "This finding is based on a simulated check. Full confirmation requires tools like Testssl.sh or Nmap.",
                    "Recommendation": "Disable all versions of SSL and TLS 1.0/1.1. Enforce support for only TLS 1.2 and TLS 1.3."
                })
        
    # --- HTTP Header Security Analysis (New Apex Module) ---
    for port_info in open_ports:
        if port_info['port'] in [80, 443]:
            missing_headers = analyze_security_headers(port_info['headers'])
            
            # Check for old X-Frame-Options (still vital)
            if 'X-Frame-Options' not in port_info['headers']:
                 missing_headers.append({"header": "X-Frame-Options", "description": "Prevents Clickjacking attacks."})

            for header_info in missing_headers:
                title = f"Missing: {header_info['header']}"
                severity, cvss, vector = calculate_severity_and_cvss(title, {})
                
                final_findings.append({
                    "Title": title,
                    "Severity": severity,
                    "CVSS": cvss,
                    "Vector": vector,
                    "VULN_TYPE": "Missing Security Header",
                    "AFFECTED_ASSET": f"HTTP Response Headers (Port {port_info['port']})",
                    "Description": f"The critical security header '{header_info['header']}' is missing. This exposes users to attacks like {header_info['description']}.",
                    "PoC": f"Checked HTTP response from {target_url} (Port {port_info['port']}); header not found.",
                    "Recommendation": f"Implement the '{header_info['header']}' header with appropriate secure values (e.g., DENY, SAMEORIGIN, or a comprehensive policy)."
                })


    # --- Directory Scan Findings ---
    for dir_info in found_dirs:
        title = f"Exposed Directory: /{dir_info['path']}"
        if dir_info.get('sensitive'):
            title = f"High: Exposed Sensitive Config File ({dir_info['path']})"

        severity, cvss, vector = calculate_severity_and_cvss(title, {})
        
        final_findings.append({
            "Title": title,
            "Severity": severity,
            "CVSS": cvss,
            "Vector": vector,
            "VULN_TYPE": "Sensitive Data Exposure/Access Control Failure",
            "AFFECTED_ASSET": f"URL Path: /{dir_info['path']}",
            "Description": "Unprotected directories/files can lead to source code disclosure, unauthorized access, or credential theft.",
            "PoC": f"Accessed path: {target_url.rstrip('/')}/{dir_info['path']} (HTTP {dir_info['status']}).",
            "Recommendation": "Configure server to deny access to sensitive paths/files (e.g., using .htaccess or web.config). Implement strong access control and ensure correct file permissions."
        })
        
    # --- Robots.txt Findings ---
    for path in disallowed_paths:
        title = f"Disallowed Path Exposed: {path}"
        severity, cvss, vector = calculate_severity_and_cvss(title, {})
        
        final_findings.append({
            "Title": title,
            "Severity": severity,
            "CVSS": cvss,
            "Vector": vector,
            "VULN_TYPE": "Information Disclosure (Robots.txt)",
            "AFFECTED_ASSET": f"URL Path: {path}",
            "Description": "The robots.txt file publicly lists paths intended to be hidden from search engines. This is not a security control and guides an attacker to sensitive areas.",
            "PoC": f"Path was extracted from {target_url}/robots.txt.",
            "Recommendation": "Remove sensitive paths from robots.txt. Implement strong, server-side access control on all restricted paths."
        })
    
    # Create Executive Summary based on severity count
    high_count = sum(1 for f in final_findings if f['Severity'] == 'High')
    medium_count = sum(1 for f in final_findings if f['Severity'] == 'Medium')
    
    summary = f"An Apex penetration test was conducted on {target_url} (IP: {ip_address}). The assessment found {len(final_findings)} total issues, including {high_count} High-severity and {medium_count} Medium-severity findings. Immediate remediation of High-severity items is MANDATORY."
    
    return {
        "Executive_Summary": summary,
        "Target_Scope": target_url,
        "Host_IP": ip_address,
        "Findings": final_findings
    }

# --- APEX HTML REPORT GENERATOR ---

def create_html_report(target, findings_data):
    """Creates a professional, ultimate HTML penetration test report."""
    
    # Advanced CSS for professional, color-coded style
    css_style = """
    <style>
        body { font-family: 'Arial', sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border: 1px solid #ddd; box-shadow: 0 0 15px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 5px; }
        h1 { text-align: center; font-size: 32px; color: #004499; }
        h2 { font-size: 24px; margin-top: 40px; color: #333; }
        h3 { font-size: 18px; margin-top: 20px; color: #d9534f; }
        .summary-box { border-left: 5px solid #0056b3; padding: 15px; background: #f4f8ff; margin-bottom: 25px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #e9ecef; color: #333; font-weight: bold; }
        .severity-High { color: white; background-color: #d9534f; font-weight: bold; padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .severity-Medium { color: white; background-color: #f0ad4e; font-weight: bold; padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .severity-Low { color: white; background-color: #5cb85c; font-weight: bold; padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .poc-box { border: 1px solid #ccc; padding: 15px; background: #f8f8f8; overflow-x: auto; margin-top: 10px; }
        .recommendation { border-top: 2px dashed #0056b3; padding-top: 15px; margin-top: 20px; }
        .vector-code { font-family: monospace; font-size: 13px; background-color: #eee; padding: 2px 5px; border-radius: 3px; }
        .note { margin-top: 50px; text-align: center; color: #666; font-size: 11px; border-top: 1px solid #eee; padding-top: 10px; }
    </style>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Apex Pentest Report - {target}</title>
        {css_style}
    </head>
    <body>
    <div class="container">
    <div class="header">
        <h1>Apex Penetration Test Report</h1>
        <h2>Target: {target}</h2>
        <p><strong>Generated by SU-AutoReport v4.0 (Apex Edition)</strong></p>
        <p>Date of Report: {time.strftime('%Y-%m-%d')}</p>
    </div>
    """

    # 1. Executive Summary
    html_content += f"""
    <h2>1. Executive Summary</h2>
    <div class="summary-box">
        <p>{findings_data["Executive_Summary"]}</p>
    </div>
    """

    # 2. Scope and Methodology
    html_content += f"""
    <h2>2. Scope and Methodology</h2>
    <ul>
        <li>Target URL: <strong>{findings_data["Target_Scope"]}</strong></li>
        <li>Resolved IP: <strong>{findings_data["Host_IP"]}</strong></li>
        <li>Methodology: Apex Black-Box testing approach, including **Advanced Security Header** and **Simulated SSL/TLS** compliance analysis.</li>
    </ul>
    """

    # 3. Findings Summary Table
    html_content += f"""
    <h2>3. Findings Summary (Total: {len(findings_data["Findings"])})</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Vulnerability Title</th>
                <th>Severity</th>
                <th>CVSS Score (Base)</th>
                <th>CVSS Vector</th>
            </tr>
        </thead>
        <tbody>
    """
    for i, finding in enumerate(findings_data["Findings"]):
        html_content += f"""
            <tr>
                <td>VULN-{i+1}</td>
                <td>{finding['Title']}</td>
                <td><span class="severity-{finding['Severity']}">{finding['Severity']}</span></td>
                <td>{finding['CVSS']}</td>
                <td><span class="vector-code">{finding['Vector']}</span></td>
            </tr>
        """
    html_content += "</tbody></table>"

    # 4. Detailed Findings Section
    html_content += f"""
    <h2>4. Detailed Findings</h2>
    """
    for i, finding in enumerate(findings_data["Findings"]):
        # Detailed Finding Header
        html_content += f"""
        <h3>4.{i+1} - {finding['Title']} (<span class="severity-{finding['Severity']}">{finding['Severity']}</span>)</h3>
        """

        # Advanced Parameter Table 
        html_content += """
        <h4>Technical Details and Classification</h4>
        <table>
            <tr><th>Classification</th><th>Vulnerability Type</th><th>Affected Asset</th><th>Vulnerability Score (CVSS)</th></tr>
            <tr><td>"""
        html_content += f"N/A</td><td>{finding['VULN_TYPE']}</td><td>{finding['AFFECTED_ASSET']}</td><td><strong>{finding['CVSS']}</strong> (<span class='vector-code'>{finding['Vector']}</span>)</td></tr>"
        html_content += "</table>"
        
        # Description
        html_content += "<h4>Description</h4>"
        html_content += f"<p>{finding['Description']}</p>"

        # Proof of Concept
        html_content += "<h4>Proof of Concept (PoC)</h4>"
        html_content += f"<div class='poc-box'><pre>{finding['PoC']}</pre></div>"

        # Recommendation
        html_content += "<h4>Recommendation</h4>"
        html_content += f"<div class='recommendation'><p>{finding['Recommendation']}</p></div>"


    # Footer and End HTML
    html_content += """
    <div class="note">This report is automatically generated by SU-AutoReport v4.0 and represents the highest level of automated penetration testing documentation.</div>
    </div>
    </body>
    </html>
    """
    
    target_clean = target.replace('http://', '').replace('https://', '').split('/')[0]
    report_filename = f"APEX_Pentest_Report_{target_clean}_{time.strftime('%Y%m%d')}.html"
    
    with open(report_filename, 'w') as f:
        f.write(html_content)
        
    return report_filename

# --- MAIN EXECUTION ---

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SU-AutoReport: APEX Pentest Report Generator. Runs ultimate advanced scans and generates an Apex HTML report.",
        usage=f"{sys.argv[0]} -t <Target_URL>"
    )
    
    parser.add_argument("-t", "--target", dest="target_url", required=True, help="Target URL (e.g., http://example.com) for which the report will be generated.")
    
    args = parser.parse_args()

    target = args.target_url
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    print(f"{Colors.YELLOW}[*] Starting APEX Report Generation for: {target}{Colors.ENDC}")
    
    findings_data = get_realtime_findings(target)

    if not findings_data["Findings"]:
        print(f"{Colors.YELLOW}[!] No significant findings were identified during the APEX scan. Generating report for documentation.{Colors.ENDC}")
    
    print(f"{Colors.GREEN}[+] Scan Data Collected. Found {len(findings_data['Findings'])} total issues.{Colors.ENDC}")
    print(f"{Colors.YELLOW}[*] Phase 2: Generating APEX HTML Report...{Colors.ENDC}")

    try:
        report_file = create_html_report(target, findings_data)
        print(f"\n{Colors.GREEN}[SUCCESS] APEX Report Generation Complete!{Colors.ENDC}")
        print("-" * 50)
        print(f"  {Colors.CYAN}{'File Path':<20}{Colors.ENDC}: {os.getcwd()}/{report_file}")
        print(f"  {Colors.CYAN}{'Report Target':<20}{Colors.ENDC}: {target}")
        print(f"  {Colors.BOLD}{Colors.YELLOW}{'NEXT STEP':<20}{Colors.ENDC}: Open the .html file in any web browser to view the APEX report.{Colors.ENDC}")
        print("-" * 50)
        
    except Exception as e:
        print(f"{Colors.RED}[FATAL] Report Generation Failed! Error: {e}{Colors.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[INTERRUPTED] Tool stopped by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[CRITICAL ERROR] An unexpected error occurred: {e}{Colors.ENDC}")
        sys.exit(1)

