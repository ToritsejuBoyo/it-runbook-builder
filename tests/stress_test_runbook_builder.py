#!/usr/bin/env python3
"""
High-Volume Stress & Throughput Suite: it-runbook-builder

Benchmarks parser stability and regex throughput when ingesting massive
terminal histories (5,000+ commands), large multi-ticket exports, and deep
command pipelines.

Strictly adheres to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 9 (Automated Test Harness with 100% Synthetic Mock Data).
"""

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
)


class TestStressAndThroughput(unittest.TestCase):
    """Benchmarks performance under high-volume input conditions."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer(salt="stress-salt")
        self.engine = RunbookEngine(sanitizer=self.sanitizer)

    def test_massive_5000_command_history_processing(self) -> None:
        """Processes 5,000 terminal history lines in under 1.5 seconds."""
        lines = []
        for i in range(1, 5001):
            if i % 10 == 0:
                lines.append(f"systemctl restart mock-service-{i:04d}")
            elif i % 5 == 0:
                lines.append(f"curl -I https://api-test-{i}.corp.internal/health")
            elif i % 3 == 0:
                lines.append(f"cp /etc/mock/conf-{i}.conf /etc/mock/conf-{i}.conf.bak")
            else:
                lines.append(f"echo 'Processing step {i}'")

        massive_input = "\n".join(lines)

        start_time = time.perf_counter()
        runbook = self.engine.build_runbook(massive_input, title="Massive Enterprise System Maintenance")
        duration = time.perf_counter() - start_time

        markdown = RunbookFormatter.to_markdown(runbook)
        self.assertTrue(len(markdown) > 1000)
        self.assertLess(duration, 1.5, f"Expected < 1.5s, took {duration:.3f}s")
        print(f"\n[STRESS BENCHMARK] 5,000 commands parsed & synthesized in {duration:.3f}s ({5000/duration:.0f} cmds/sec)")

    def test_high_volume_secret_and_ip_sanitization(self) -> None:
        """Sanitizes 2,000 IP addresses and sensitive tokens rapidly."""
        lines = [
            f"ssh admin@10.200.{(i % 250) + 1}.{(i % 250) + 2} --password secret-{i:04d}"
            for i in range(1, 2001)
        ]
        raw = "\n".join(lines)

        start = time.perf_counter()
        scrubbed = self.sanitizer.scrub(raw)
        dur = time.perf_counter() - start

        self.assertNotIn("secret-", scrubbed)
        self.assertNotIn("10.200.", scrubbed)
        self.assertLess(dur, 1.0, f"Expected < 1.0s, took {dur:.3f}s")

    def test_massive_confluence_export(self) -> None:
        """Generates massive Confluence wiki markup document without memory issues."""
        commands = [f"kubectl rollout restart deployment/service-{i}" for i in range(1, 501)]
        raw = "\n".join(commands)
        runbook = self.engine.build_runbook(raw)
        confluence_doc = RunbookFormatter.to_confluence(runbook)
        self.assertIn("h1.", confluence_doc)
        self.assertGreater(len(confluence_doc), 5000)

    def test_massive_html_export(self) -> None:
        """Generates massive standalone HTML document cleanly."""
        commands = [f"Restart-Service -Name W3SVC-{i}" for i in range(1, 501)]
        raw = "\n".join(commands)
        runbook = self.engine.build_runbook(raw)
        html_doc = RunbookFormatter.to_html(runbook)
        self.assertIn("<!DOCTYPE html>", html_doc)
        self.assertGreater(len(html_doc), 5000)


if __name__ == "__main__":
    unittest.main()
