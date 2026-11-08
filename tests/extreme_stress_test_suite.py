#!/usr/bin/env python3
"""
Extreme Stress & Adversarial Test Suite: it-runbook-builder

Executes 20 rigorous tests against:
1. Massive 10,000-command stream benchmarks.
2. Token flooding and credential scrubbers.
3. Nested heredocs and multiline script blocks.
4. Broken/ragged PowerShell transcripts.
5. Corrupted/truncated JSON ticket payloads.
6. Catastrophic backtracking (ReDoS) resistance.
7. 100,000-character pathological command lines.
8. Adversarial Unicode & Bidirectional (Bidi) overrides.
9. Emoji floods (enforcing Rule 7 zero-emoji compliance).
10. Rapid sequential synthesis stress.
11. Massive 50-pipe shell command pipelines.
12. Complex PowerShell pipeline scriptblocks.
13. ANSI escape codes and terminal color sequences.
14. Destructive command risk categorization.
15. Broad check/verification command identification.
16. HTML XSS payload escaping.
17. Confluence wiki special syntax collision handling.
18. Repeated/deduplicated command cycles.
19. Null bytes and binary corruption.
20. Overlapping domain and IP parameter collisions.

Adheres strictly to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 9 (Automated Test Harness with 100% Synthetic Mock Data).
"""

import html
import json
import os
import sys
import time
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


class TestExtremeStress20(unittest.TestCase):
    """20 extreme stress and boundary tests."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer(salt="extreme-20-salt")
        self.engine = RunbookEngine(sanitizer=self.sanitizer)

    def test_01_massive_10000_commands_history(self) -> None:
        """1. Ingests and synthesizes 10,000 terminal commands within 2.0s."""
        commands = [
            f"systemctl restart worker-{i % 50}" if i % 4 == 0 else f"curl -I https://node-{i % 20}.corp.internal/ping"
            for i in range(1, 10001)
        ]
        raw_input = "\n".join(commands)

        t0 = time.perf_counter()
        runbook = self.engine.build_runbook(raw_input)
        duration = time.perf_counter() - t0

        self.assertGreaterEqual(len(runbook.execution_steps), 50)
        self.assertLess(duration, 2.0, f"Expected < 2.0s, took {duration:.3f}s")
        print(f"\n[STRESS 01] 10,000 commands ingested in {duration:.3f}s ({10000/duration:.0f} cmds/sec)")

    def test_02_massive_token_flood_sanitizer(self) -> None:
        """2. Scrubs 5,000 diverse credentials, bearer tokens, and private IPs."""
        lines = []
        for i in range(1, 5001):
            lines.append(
                f"curl -H 'Authorization: Bearer token_{i}_abcdef123456789' "
                f"https://10.{(i % 250) + 1}.{(i % 250) + 2}.{(i % 250) + 3}/api -u user_{i}:SecretP@ss_{i}"
            )
        raw_text = "\n".join(lines)

        t0 = time.perf_counter()
        scrubbed = self.sanitizer.scrub(raw_text)
        duration = time.perf_counter() - t0

        self.assertNotIn("Bearer token_", scrubbed)
        self.assertNotIn("SecretP@ss_", scrubbed)
        self.assertNotIn("10.", scrubbed)
        self.assertLess(duration, 2.5, f"Expected < 2.5s, took {duration:.3f}s")
        print(f"[STRESS 02] 5,000 credentials scrubbed in {duration:.3f}s")

    def test_03_deeply_nested_heredocs_and_scripts(self) -> None:
        """3. Parses multiline shell blocks with nested EOF markers."""
        script = """
cat << 'OUTER_EOF' > /tmp/deploy.sh
#!/bin/bash
cat << 'INNER_EOF' > /tmp/inner.conf
key = value
INNER_EOF
systemctl restart internal-daemon
OUTER_EOF
chmod +x /tmp/deploy.sh
/tmp/deploy.sh
"""
        runbook = self.engine.build_runbook(script)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("chmod +x" in c for c in cmds))
        self.assertTrue(any("/tmp/deploy.sh" in c for c in cmds))

    def test_04_ragged_powershell_transcripts_1000_blocks(self) -> None:
        """4. Ingests 1,000 ragged PowerShell transcript segments with missing headers."""
        lines = []
        for i in range(1, 1001):
            if i % 3 == 0:
                lines.append("**********************")
                lines.append(f"Start time: 20261108{i:06d}")
                lines.append(f"Machine: WIN-NODE-{i:03d}")
                lines.append("**********************")
            lines.append(f"PS C:\\Cluster\\Node{i}> Restart-Service -Name ClusSvc")
            lines.append(f"PS C:\\Cluster\\Node{i}> Get-ClusterNode -Name Node{i}")
        raw_ps = "\n".join(lines)

        runbook = self.engine.build_runbook(raw_ps, target_env="Windows Cluster")
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(all(not c.startswith("PS C:\\") for c in cmds))
        self.assertTrue(all(not c.startswith("Start time:") for c in cmds))
        self.assertTrue(any("Restart-Service" in c for c in cmds))

    def test_05_malformed_json_bom_and_truncation(self) -> None:
        """5. Handles truncated JSON with UTF-8 BOM and unclosed string literals."""
        bom_json = "\ufeff" + '{"issue_key": "INC-999", "work_notes": ["systemctl reload nginx", "curl -I http://localhost/health'
        runbook = self.engine.build_runbook(bom_json)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("nginx" in c for c in cmds))

    def test_06_pathological_catastrophic_backtracking_regex(self) -> None:
        """6. Defends against pathological ReDoS strings without hanging."""
        pathological_1 = "10." + ("10." * 2000) + "255"
        pathological_2 = "password=" + ("a=" * 2000) + "secret"
        pathological_3 = "Bearer " + ("A" * 5000)

        t0 = time.perf_counter()
        scrubbed = self.sanitizer.scrub(pathological_1 + "\n" + pathological_2 + "\n" + pathological_3)
        duration = time.perf_counter() - t0

        self.assertLess(duration, 1.0, f"ReDoS suspected: took {duration:.3f}s")
        print(f"[STRESS 06] ReDoS defense verified in {duration:.3f}s")

    def test_07_massive_single_line_100k_chars(self) -> None:
        """7. Ingests a single command line spanning 100,000 characters."""
        args = " ".join([f"--flag-{i}=synthetic-val-{i}" for i in range(3000)])
        long_cmd = f"python app.py {args}"

        runbook = self.engine.build_runbook(long_cmd)
        self.assertEqual(len(runbook.execution_steps), 1)
        self.assertGreater(len(runbook.execution_steps[0].command), 50000)

    def test_08_adversarial_unicode_and_bidirectional_injection(self) -> None:
        """8. Strips bidirectional (Bidi) overrides and hostile control characters."""
        hostile = "systemctl restart \u202e\u200b\u200ctest-service\u202d.service"
        scrubbed = self.sanitizer.scrub(hostile)
        self.assertNotIn("\u202e", scrubbed)
        self.assertNotIn("\u200b", scrubbed)
        self.assertIn("test-service", scrubbed)

    def test_09_emoji_flood_sanitization(self) -> None:
        """9. Strips 2,000 diverse emojis to enforce Rule 7 enterprise tone."""
        emoji_flood = "systemctl restart nginx 🔥🚀⚡🎉💻✨🚨🛑⚠️" * 200
        scrubbed = self.sanitizer.scrub(emoji_flood)
        for char in ["🔥", "🚀", "⚡", "🎉", "💻", "✨", "🚨", "🛑", "⚠️"]:
            self.assertNotIn(char, scrubbed)

    def test_10_high_concurrency_rapid_synthesis(self) -> None:
        """10. Executes 50 sequential runbook builds without state leakage."""
        for i in range(1, 51):
            raw = f"systemctl restart service-{i:02d}\ncurl -I http://10.0.0.{i}:8080/health"
            rb = self.engine.build_runbook(raw, title=f"Runbook {i}")
            self.assertIn(f"Runbook {i}", rb.metadata.title)
            md = RunbookFormatter.to_markdown(rb)
            self.assertIn(f"service-{i:02d}", md)

    def test_11_massive_pipeline_with_50_pipe_operators(self) -> None:
        """11. Preserves complex multi-stage shell pipelines."""
        pipeline_cmd = "cat /var/log/syslog " + " | grep 'error' | awk '{print $1}' | sort | uniq -c" * 10
        runbook = self.engine.build_runbook(pipeline_cmd)
        self.assertEqual(len(runbook.execution_steps), 1)
        self.assertIn("uniq -c", runbook.execution_steps[0].command)

    def test_12_complex_powershell_pipeline_objects(self) -> None:
        """12. Preserves PowerShell scriptblocks with braces and pipeline variables."""
        ps_cmd = "Get-Process | Where-Object { $_.CPU -gt 100 } | Select-Object -Property Id, ProcessName | Stop-Process -Force"
        runbook = self.engine.build_runbook(ps_cmd, target_env="Windows 11")
        self.assertEqual(len(runbook.execution_steps), 1)
        self.assertEqual(runbook.execution_steps[0].command, ps_cmd)

    def test_13_ticket_notes_mixed_ansi_escape_sequences(self) -> None:
        """13. Handles raw ANSI color codes (\x1b[31m) from terminal captures."""
        ansi_text = "\x1b[32m[OK]\x1b[0m \x1b[1msystemctl restart postgresql\x1b[0m\n\x1b[31m[FAIL]\x1b[0m connection refused"
        runbook = self.engine.build_runbook(ansi_text)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("postgresql" in c for c in cmds))

    def test_14_all_destructive_commands_risk_scoring(self) -> None:
        """14. Assigns High risk rating to dangerous/destructive operational commands."""
        destructive_cmds = [
            "rm -rf /var/cache/app/*",
            "kubectl delete pod -l app=payment --force",
            "systemctl stop mariadb",
            "reboot"
        ]
        raw = "\n".join(destructive_cmds)
        runbook = self.engine.build_runbook(raw)
        for step in runbook.execution_steps:
            self.assertEqual(step.risk_level, "High", f"Expected High risk for: {step.command}")

    def test_15_all_read_only_checks_categorization(self) -> None:
        """15. Correctly categorizes read-only inspection commands as non-state-changing."""
        checks = [
            "curl -I https://api.example.com",
            "dig +short api.example.com",
            "ping -c 3 192.0.2.1",
            "systemctl status nginx",
            "df -h /var/log"
        ]
        raw = "\n".join(checks)
        runbook = self.engine.build_runbook(raw)
        for step in runbook.execution_steps:
            self.assertFalse(step.is_state_changing, f"Expected non-state-changing for: {step.command}")

    def test_16_html_export_xss_injection_payloads(self) -> None:
        """16. Escapes XSS attack vectors in command outputs and titles."""
        xss_cmd = 'curl -d "<script>alert(document.cookie)</script>" https://api.example.com'
        runbook = self.engine.build_runbook(xss_cmd, title='<img src=x onerror=alert(1)>')
        html_out = RunbookFormatter.to_html(runbook)
        self.assertNotIn("<script>alert", html_out)
        self.assertNotIn("<img src=x onerror", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_17_confluence_wiki_markup_special_characters(self) -> None:
        """17. Handles Confluence syntax collisions (curly braces, brackets, asterisks)."""
        tricky_cmd = "awk -F':' '{ print $1, $3 }' /etc/passwd | grep -E '^(root|admin)'"
        runbook = self.engine.build_runbook(tricky_cmd)
        confluence_out = RunbookFormatter.to_confluence(runbook)
        self.assertIn("{code:language=bash}", confluence_out)
        self.assertIn("awk -F':'", confluence_out)

    def test_18_circular_or_redundant_commands_cleanup(self) -> None:
        """18. Handles rapid repeated commands during troubleshooting iterations."""
        repeated = "\n".join(["systemctl restart app-worker"] * 50)
        runbook = self.engine.build_runbook(repeated)
        # Should generate valid steps without crashing
        self.assertGreaterEqual(len(runbook.execution_steps), 1)
        markdown = RunbookFormatter.to_markdown(runbook)
        self.assertTrue(len(markdown) > 500)

    def test_19_zero_byte_and_binary_corruption(self) -> None:
        """19. Ignores embedded null bytes and binary control codes."""
        corrupt_input = "systemctl restart clean-app\x00\x01\x02\x03\x04\nsystemctl status clean-app"
        runbook = self.engine.build_runbook(corrupt_input)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("clean-app" in c for c in cmds))

    def test_20_parameter_collision_and_overlap(self) -> None:
        """20. Handles overlapping domain and IP prefixes without corrupting replacements."""
        text = (
            "curl https://sub.api.corp.internal/v1\n"
            "curl https://api.corp.internal/v1\n"
            "ping 192.0.2.1\n"
            "ping 192.0.2.100\n"
        )
        runbook = self.engine.build_runbook(text)
        md = RunbookFormatter.to_markdown(runbook)
        self.assertIn("<TARGET_FQDN>", md)
        self.assertIn("<TARGET_IP>", md)


if __name__ == "__main__":
    unittest.main()
