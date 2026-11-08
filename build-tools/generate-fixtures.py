#!/usr/bin/env python3
"""
Synthetic Mock Fixture Generator for it-runbook-builder.

Generates 4 realistic enterprise operational telemetry fixtures:
1. fixture-bash-ssl-renewal.txt (Bash history with Nginx SSL renewal and systemctl)
2. fixture-powershell-iis-recycle.txt (PowerShell transcript recycling IIS AppPool)
3. fixture-jira-ticket-dns-cutover.json (Jira/ServiceNow ITSM ticket resolution notes)
4. fixture-messy-incident-chat.txt (Incident Slack/Teams bridge chat transcript)

Strictly adheres to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 9 (Automated Test Harness with 100% Synthetic Mock Data).
"""

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def generate_bash_ssl_renewal():
    content = """# Bash History: Production Nginx SSL Certificate Renewal
cd /etc/ssl/certs
ls -la
whoami
openssl x509 -in /etc/ssl/certs/api-gateway.crt -noout -dates
cp /etc/ssl/certs/api-gateway.crt /etc/ssl/certs/api-gateway.crt.bak
cp /etc/ssl/private/api-gateway.key /etc/ssl/private/api-gateway.key.bak
certbot certonly --standalone -d api.corp.internal --non-interactive --agree-tos -m admin-devops@corp.internal --post-hook "systemctl reload nginx"
chmod 600 /etc/ssl/private/api-gateway.key
chown root:root /etc/ssl/certs/api-gateway.crt
nginx -t
systemctl reload nginx
systemctl status nginx
curl -I https://api.corp.internal/healthz
openssl s_client -connect 10.100.4.15:443 -servername api.corp.internal < /dev/null | openssl x509 -noout -dates
"""
    path = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
    path.write_text(content.strip() + "\n", encoding="utf-8")
    print(f"[+] Generated: {path}")


def generate_powershell_iis_recycle():
    content = """**********************
Windows PowerShell transcript start
Start time: 20261108041520
Username: SYNTHETIC\\admin-service
RunAs User: SYNTHETIC\\admin-service
Configuration Name: 
Machine: WIN-PROD-APP01 (Microsoft Windows Server 2022 Datacenter)
Host Application: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
Process ID: 8192
PSVersion: 5.1.20348.1
**********************
Transcript started, output file is C:\\Logs\\PowerShell_transcript.txt
PS C:\\Windows\\system32> Test-Connection -ComputerName app-backend01.corp.local -Count 2
PS C:\\Windows\\system32> Get-Service -Name W3SVC | Select-Object Status, Name, DisplayName
PS C:\\Windows\\system32> Get-IISAppPool -Name "PaymentProcessingPool"
PS C:\\Windows\\system32> Restart-WebAppPool -Name "PaymentProcessingPool"
PS C:\\Windows\\system32> Stop-Service -Name W3SVC
PS C:\\Windows\\system32> Remove-Item -Path "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Temporary ASP.NET Files\\root\\*" -Recurse -Force
PS C:\\Windows\\system32> Start-Service -Name W3SVC
PS C:\\Windows\\system32> Get-Service -Name W3SVC
PS C:\\Windows\\system32> Invoke-WebRequest -Uri "http://10.200.12.50:8080/health" -UseBasicParsing
**********************
Windows PowerShell transcript end
End time: 20261108041830
**********************
"""
    path = FIXTURES_DIR / "fixture-powershell-iis-recycle.txt"
    path.write_text(content.strip() + "\n", encoding="utf-8")
    print(f"[+] Generated: {path}")


def generate_jira_ticket_dns_cutover():
    data = {
        "issue_key": "INFRA-4892",
        "summary": "Production DNS Cutover for Payment Gateway Endpoint",
        "status": "Closed",
        "reporter": "lead-architect@synthetic-corp.com",
        "assignee": "sre-engineer@synthetic-corp.com",
        "work_notes": [
            "Initiating scheduled change CHG0098231 at 03:00 UTC.",
            "Pre-flight check: Verify existing DNS propagation using dig +short gateway.corp.internal @10.0.0.2",
            "Lowered TTL from 3600 to 60 seconds on Route53 zone Z102938482.",
            "Executed API token update: curl -H 'Authorization: Bearer mock-secret-token-xyz-12345' https://api.corp.internal/v1/config",
            "Updated DNS A record pointing gateway.corp.internal to 10.50.20.100.",
            "Verification command: dig gateway.corp.internal +short",
            "Health check probe: curl -i -s https://gateway.corp.internal/ping",
            "Observed successful response 200 OK with latency 14ms.",
            "Change completed successfully. Raised TTL back to 3600."
        ],
        "resolution": "DNS A record updated to point to new active load balancer. Verified traffic routing."
    }
    path = FIXTURES_DIR / "fixture-jira-ticket-dns-cutover.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Generated: {path}")


def generate_messy_incident_chat():
    content = """[02:14:10] <sre_alex> Disk alert triggered on prod-elastic-04. Volume /data is at 98% full.
[02:15:05] <oncall_dev> Looking at it now. Logging in via bastion.
[02:15:40] <oncall_dev> Checked volume: `df -h /data`
[02:16:12] <oncall_dev> Found massive unrotated logs in `/var/log/elasticsearch/`.
[02:17:00] <sre_alex> Did logrotate fail? Check `systemctl status logrotate`
[02:17:45] <oncall_dev> Yes, logrotate was masked. Let me unmask it: `systemctl unmask logrotate`
[02:18:20] <oncall_dev> Force rotating logs now: `logrotate -f /etc/logrotate.d/elasticsearch`
[02:19:10] <oncall_dev> Cleaning stale gzipped files older than 30 days: `find /var/log/elasticsearch/ -name "*.log.gz" -mtime +30 -delete`
[02:20:00] <oncall_dev> Restarting the elasticsearch cluster node: `systemctl restart elasticsearch`
[02:20:45] <sre_alex> Verify cluster health: `curl -s http://10.240.1.80:9200/_cluster/health`
[02:21:15] <oncall_dev> Cluster status is green. Available disk space on /data is now 42% (reclaimed 320 GB).
[02:22:00] <sre_alex> Alert cleared in Datadog. Document this as an SOP so L1 can run it next time.
"""
    path = FIXTURES_DIR / "fixture-messy-incident-chat.txt"
    path.write_text(content.strip() + "\n", encoding="utf-8")
    print(f"[+] Generated: {path}")


def main():
    print("[*] Generating synthetic test fixtures for it-runbook-builder...")
    generate_bash_ssl_renewal()
    generate_powershell_iis_recycle()
    generate_jira_ticket_dns_cutover()
    generate_messy_incident_chat()
    print("[+] All fixtures successfully generated.")


if __name__ == "__main__":
    main()
