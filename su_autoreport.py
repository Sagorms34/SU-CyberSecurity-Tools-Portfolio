
#!/usr/bin/env python3
# SU-AutoReport v4.0: Super Advanced Report Generator (Apex Edition)

import requests
import argparse
import sys
import socket
import datetime
import random
import time

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

# --- BANNER FUNCTION (MUST BE DEFINED HERE) ---
# FIX: Placed this function definition before main() to resolve NameError
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
# This is a simplified version for demonstration. You can add complex logic here.

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
    
    # Example Headers to Check
    CRITICAL_HEADERS = {
        'Strict-Transport-Security': False,
        'Content-Security-Policy': False,
        'X-Frame-Options': False,
        'X-Content-Type-Options': False,
    }

    try:
        response = requests.get(target, timeout=10)
        
        for header in CRITICAL_HEADERS.keys():
            if header in response.headers:
                CRITICAL_HEADERS[header] = True
            else:
                header_findings.append(f"Missing {header} header.")
        
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[ERROR] Header check failed: {e}{Colors.ENDC}")

    return header_findings

def generate_html_report(target_url, ip_address, open_ports, header_findings):
    """Generates a professional HTML report (Apex Edition)."""
    report_date = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = f"APEX_Pentest_Report_{target_url.split('//')[-1].replace('.', '_').replace('/', '')}_{report_date}.html"
    
    # Simplified Finding Generation (For Demonstration)
    findings = []
    if open_ports:
        findings.append({
            'title': 'Open Ports Detected',
            'severity': 'Medium',
            'description': f"The following ports are open: {', '.join(map(str, open_ports))}. This increases the attack surface.",
            'recommendation': 'Restrict access to these ports via firewall rules (ACLs) to trusted IP ranges only.'
        })
    if header_findings:
        findings.append({
            'title': 'Missing Security Headers',
            'severity': 'Low',
            'description': f"The application is missing critical security headers: {', '.join(header_findings)}.",
            'recommendation': 'Implement all critical HTTP Security Headers (HSTS, CSP, X-Frame-Options) to mitigate common web vulnerabilities.'
        })

    # --- HTML Template (A very simplified example) ---
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Apex Pentest Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background-color: #004d40; color: white; padding: 20px; text-align: center; }}
            .finding {{ border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 5px; }}
            .severity-Medium {{ background-color: #ffcc00; }}
            .severity-Low {{ background-color: #c6e2ff; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SU-AutoReport V4.0 - Apex Penetration Test Report</h1>
            <p>Target: {target_url} (IP: {ip_address}) | Date: {report_date}</p>
        </div>
        <h2>3. Detailed Findings</h2>
        {''.join([
            f'<div class="finding severity-{f["severity"]}"><h3>{f["title"]} ({f["severity"]})</h3><p><strong>Description:</strong> {f["description"]}</p><p><strong>Recommendation:</strong> {f["recommendation"]}</p></div>'
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
    # 1. Print Banner
    print_banner() # This will now work because print_banner is defined above

    parser = argparse.ArgumentParser(
        description="SU-AutoReport: Automated penetration testing and professional report generator.",
        usage=f"{sys.argv[0]} -t <Target_URL>"
    )
    
    parser.add_argument("-t", "--target", dest="target_url", required=True, help="Target URL (e.g., https://example.com).")
    
    args = parser.parse_args()
    target_url = args.target_url

    print(f"{Colors.CYAN}[INFO] Starting Super Advanced Report Generation for: {target_url}{Colors.ENDC}")
    
    # 2. Resolve Target
    ip_address, hostname = resolve_target(target_url)
    print(f"{Colors.CYAN}[INFO] Target IP Resolved to: {ip_address}{Colors.ENDC}")
    time.sleep(1) # Simulate delay

    # 3. Perform Scans
    print(f"\n{Colors.MAGENTA}Phase 1: Executing Real-Time Multi-Vector Scans...{Colors.ENDC}")
    open_ports = scan_ports(ip_address)
    header_findings = check_security_headers(target_url)
    print(f"{Colors.GREEN}[+] Scan Data Collected. Found {len(open_ports)} open ports and {len(header_findings)} header issues.{Colors.ENDC}")
    time.sleep(1)

    # 4. Generate Report
    print(f"\n{Colors.MAGENTA}Phase 2: Generating Professional HTML Report...{Colors.ENDC}")
    generate_html_report(target_url, ip_address, open_ports, header_findings)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[INTERRUPTED] Tool stopped by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[CRITICAL ERROR] An unexpected error occurred: {e}{Colors.ENDC}")
        # In a real tool, you would log this error.
        sys.exit(1)

