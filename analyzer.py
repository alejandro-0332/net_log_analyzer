import os
import re
import json
from collections import Counter
from dataclasses import dataclass
from typing import List, Dict, Any
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

@dataclass
class SecurityMetrics:
    total_requests: int
    unique_ips: int
    status_codes: Dict[str, int]
    suspicious_events: List[str]
    top_offenders: List[tuple]

class LogParser:
    """Parses web server/network access logs and extracts security anomalies."""
    
    # Signatures for common web attacks and reconnaissance attempts
    SUSPICIOUS_PATTERNS = [
        r"(\.\./|\.\.\\)",             # Directory Traversal
        r"(union.*select|select.*from)", # SQL Injection
        r"(<script|alert\(|onerror=)", # Cross-Site Scripting (XSS)
        r"(/etc/passwd|/bin/sh)",      # Unauthorized System File Access
        r"(\.env|config\.json|wp-login)" # Sensitive File & Credential Reconnaissance
    ]

    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path

    def parse(self) -> SecurityMetrics:
        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(f"Log file not found: {self.log_file_path}")

        ip_counter = Counter()
        status_counter = Counter()
        suspicious_matches = []
        total_lines = 0

        # Standard Nginx/Apache Combined Log Regex
        log_pattern = re.compile(
            r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?P<method>\w+) (?P<uri>.*?) HTTP/.*?" (?P<status>\d{3})'
        )

        with open(self.log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                total_lines += 1
                match = log_pattern.search(line)
                if match:
                    ip = match.group("ip")
                    uri = match.group("uri")
                    status = match.group("status")

                    ip_counter[ip] += 1
                    status_counter[status] += 1

                    # Identify suspicious request signatures
                    for pattern in self.SUSPICIOUS_PATTERNS:
                        if re.search(pattern, uri, re.IGNORECASE):
                            suspicious_matches.append(
                                f"IP: {ip} | URI: {uri} | Status: {status}"
                            )
                            break

        return SecurityMetrics(
            total_requests=total_lines,
            unique_ips=len(ip_counter),
            status_codes=dict(status_counter),
            suspicious_events=suspicious_matches[:20],  # Window limit for token efficiency
            top_offenders=ip_counter.most_common(5)
        )


class LLMSecurityAuditor:
    """Leverages an LLM agent to triage metrics and compile structured incident reports."""

    def __init__(self, model: str = "gpt-4o-mini"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("Environment variable OPENAI_API_KEY is missing.")
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate_incident_report(self, metrics: SecurityMetrics) -> str:
        system_prompt = (
            "You are a Tier-2 SOC Analyst and Incident Response Engineer. "
            "Your task is to analyze aggregated network/web server log telemetry, "
            "identify potential security incidents or attack vectors, assess the threat level, "
            "and produce an executive incident triage report in Markdown format."
        )

        user_content = f"""
Analyze the following parsed log telemetry and compile an incident response report:

- Total Requests: {metrics.total_requests}
- Unique Client IPs: {metrics.unique_ips}
- HTTP Status Code Distribution: {json.dumps(metrics.status_codes)}
- Top 5 Traffic Sources (IP, Hit Count): {metrics.top_offenders}
- Detected Suspicious Events:
{chr(10).join(f"  * {event}" for event in metrics.suspicious_events) if metrics.suspicious_events else "  * None detected."}

The Markdown report must strictly include the following sections:
1. Executive Summary & Calculated Threat Level (LOW | MEDIUM | HIGH | CRITICAL)
2. Indicators of Compromise (IoCs)
3. Observed Attack Techniques & MITRE ATT&CK Mapping
4. Immediate Remediation & Hardening Recommendations (Firewall, WAF, Rate-limiting, Patching)
"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content


def main():
    log_file = "sample_access.log"
    output_report = "incident_report.md"

    # Generate synthetic telemetry if no local file exists
    if not os.path.exists(log_file):
        with open(log_file, "w", encoding="utf-8") as f:
            f.write('192.168.1.50 - - [20/Sep/2026:10:15:32 +0200] "GET /api/v1/health HTTP/1.1" 200 452\n')
            f.write('203.0.113.195 - - [20/Sep/2026:10:16:01 +0200] "GET /../../etc/passwd HTTP/1.1" 403 162\n')
            f.write('203.0.113.195 - - [20/Sep/2026:10:16:05 +0200] "GET /.env HTTP/1.1" 404 162\n')
            f.write('203.0.113.195 - - [20/Sep/2026:10:16:12 +0200] "POST /login?user=\' OR 1=1-- HTTP/1.1" 401 540\n')
            f.write('10.0.0.12 - - [20/Sep/2026:10:17:00 +0200] "GET /dashboard HTTP/1.1" 200 1200\n')

    print(f"[*] Parsing log stream: {log_file}...")
    parser = LogParser(log_file)
    metrics = parser.parse()

    print("[*] Dispatching security telemetry to LLM agent...")
    auditor = LLMSecurityAuditor()
    report = auditor.generate_incident_report(metrics)

    with open(output_report, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[+] Security analysis complete. Report exported to: {output_report}")


if __name__ == "__main__":
    main()
