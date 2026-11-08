#!/usr/bin/env python3
"""
Automated Test Harness: it-runbook-builder (Rule 9)

Validates zero-dependency operational telemetry ingestion across:
- Bash/Zsh terminal histories
- PowerShell transcripts
- ITSM ticket work notes (Jira / ServiceNow JSON)
- Incident chat bridge logs
- Secret / PII sanitization (Rule 4)
- 8 mandatory ITIL/SOC 2 runbook sections
- Multi-format output generation (Markdown, Confluence, HTML, JSON, Proof-of-Work)

Returns exit code 0 on complete pass.
"""

import json
import os
import sys
import unittest
from pathlib import Path

# Add scripts directory to module import path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from runbook_builder import (
    Sanitizer,
    TelemetryParser,
    RunbookEngine,
    RunbookFormatter,
    Runbook,
    RunbookStep
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestRunbookBuilderHarness(unittest.TestCase):
    """Core validation test suite for it-runbook-builder."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer(salt="test-salt")
        self.engine = RunbookEngine(sanitizer=self.sanitizer)

    def test_sanitizer_secret_redaction(self) -> None:
        """Verifies passwords, bearer tokens, AWS keys, and private IPs are redacted."""
        raw_text = (
            "curl -H 'Authorization: Bearer secret-token-xyz-123' https://10.240.1.15/api\n"
            "mysql -u root -p SuperSecretP@ssw0rd! -h db01.corp.internal\n"
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        )
        scrubbed = self.sanitizer.scrub(raw_text)
        self.assertNotIn("secret-token-xyz-123", scrubbed)
        self.assertNotIn("SuperSecretP@ssw0rd!", scrubbed)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertNotIn("10.240.1.15", scrubbed)
        self.assertIn("192.0.2.", scrubbed)
        self.assertIn("[REDACTED_SECRET]", scrubbed)
        self.assertIn("[REDACTED_AWS_ACCESS_KEY]", scrubbed)

    def test_bash_ssl_renewal_fixture(self) -> None:
        """Tests parsing of Bash Nginx SSL certificate renewal history."""
        fixture_file = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
        self.assertTrue(fixture_file.exists(), "fixture-bash-ssl-renewal.txt must exist")
        raw_text = fixture_file.read_text(encoding="utf-8")

        runbook = self.engine.build_runbook(raw_text)
        self.assertIn("Certificate Renewal", runbook.metadata.title)
        self.assertGreaterEqual(len(runbook.execution_steps), 4)

        # Confirm noise commands (cd, ls, whoami) were filtered
        executed_cmds = [s.command for s in runbook.execution_steps]
        self.assertFalse(any(cmd.startswith("cd ") for cmd in executed_cmds))
        self.assertFalse(any(cmd == "ls -la" for cmd in executed_cmds))
        self.assertFalse(any(cmd == "whoami" for cmd in executed_cmds))

        # Confirm critical commands present
        self.assertTrue(any("certbot" in cmd for cmd in executed_cmds))
        self.assertTrue(any("nginx -t" in cmd or "systemctl reload" in cmd for cmd in executed_cmds))

        # Confirm rollback and verification derived
        self.assertGreaterEqual(len(runbook.verification_steps), 1)
        self.assertGreaterEqual(len(runbook.rollback_steps), 1)

    def test_powershell_iis_recycle_fixture(self) -> None:
        """Tests parsing of PowerShell IIS app pool recycling transcript."""
        fixture_file = FIXTURES_DIR / "fixture-powershell-iis-recycle.txt"
        self.assertTrue(fixture_file.exists())
        raw_text = fixture_file.read_text(encoding="utf-8")

        runbook = self.engine.build_runbook(raw_text, target_env="Windows Server 2022")
        self.assertIn("IIS", runbook.metadata.title)
        self.assertEqual(runbook.metadata.target_environment, "Windows Server 2022")

        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("Restart-WebAppPool" in c for c in cmds))
        self.assertTrue(any("Stop-Service -Name W3SVC" in c for c in cmds))
        self.assertTrue(any("Start-Service -Name W3SVC" in c for c in cmds))

        # Confirm prompt 'PS C:\Windows\system32>' was stripped
        self.assertFalse(any(c.startswith("PS C:\\") for c in cmds))

    def test_jira_ticket_dns_cutover_fixture(self) -> None:
        """Tests parsing of JSON ticket notes for DNS cutover."""
        fixture_file = FIXTURES_DIR / "fixture-jira-ticket-dns-cutover.json"
        self.assertTrue(fixture_file.exists())
        raw_text = fixture_file.read_text(encoding="utf-8")

        runbook = self.engine.build_runbook(raw_text)
        self.assertIn("DNS", runbook.metadata.title)

        # Confirm Bearer token was scrubbed
        markdown = RunbookFormatter.to_markdown(runbook)
        self.assertNotIn("mock-secret-token-xyz-12345", markdown)
        self.assertNotIn("10.50.20.100", markdown)

    def test_messy_incident_chat_fixture(self) -> None:
        """Tests extraction of commands from a chaotic incident bridge chat."""
        fixture_file = FIXTURES_DIR / "fixture-messy-incident-chat.txt"
        self.assertTrue(fixture_file.exists())
        raw_text = fixture_file.read_text(encoding="utf-8")

        runbook = self.engine.build_runbook(raw_text)
        self.assertIn("Filesystem Capacity", runbook.metadata.title)

        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("logrotate" in c for c in cmds))
        self.assertTrue(any("find" in c and "delete" in c for c in cmds))

    def test_format_confluence_markup(self) -> None:
        """Tests Confluence wiki format output generator."""
        fixture_file = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
        raw_text = fixture_file.read_text(encoding="utf-8")
        runbook = self.engine.build_runbook(raw_text)

        confluence_out = RunbookFormatter.to_confluence(runbook)
        self.assertIn("h1.", confluence_out)
        self.assertIn("{code:language=bash}", confluence_out)
        self.assertIn("h2. 1. Prerequisites", confluence_out)

    def test_format_html_output(self) -> None:
        """Tests standalone responsive HTML output generator."""
        fixture_file = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
        raw_text = fixture_file.read_text(encoding="utf-8")
        runbook = self.engine.build_runbook(raw_text)

        html_out = RunbookFormatter.to_html(runbook)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("<title>", html_out)
        self.assertIn("class=\"container\"", html_out)

    def test_format_json_output(self) -> None:
        """Tests structured JSON output serialization and schema."""
        fixture_file = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
        raw_text = fixture_file.read_text(encoding="utf-8")
        runbook = self.engine.build_runbook(raw_text)

        json_out = RunbookFormatter.to_json(runbook)
        data = json.loads(json_out)
        self.assertIn("metadata", data)
        self.assertIn("execution_steps", data)
        self.assertIn("verification_steps", data)
        self.assertIn("rollback_steps", data)
        self.assertIn("troubleshooting", data)

    def test_proof_of_work_output(self) -> None:
        """Tests portfolio case study proof-of-work formatter."""
        fixture_file = FIXTURES_DIR / "fixture-bash-ssl-renewal.txt"
        raw_text = fixture_file.read_text(encoding="utf-8")
        runbook = self.engine.build_runbook(raw_text)

        pow_out = RunbookFormatter.to_proof_of_work(runbook)
        self.assertIn("Case Study", pow_out)
        self.assertIn("Key Engineering Decisions", pow_out)
        self.assertIn("Zero-Outage Pre-Flight Assertions", pow_out)


if __name__ == "__main__":
    unittest.main()
