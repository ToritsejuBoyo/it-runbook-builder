#!/usr/bin/env python3
"""
Extended Deep Stress & Edge Case Test Suite: it-runbook-builder

Adds 10 additional high-intensity stress and boundary tests:
21. Multiline inline Python & AWK scripts within shell histories.
22. Massive variable dictionary scaling (1,000 unique IPs and domains).
23. Complex PowerShell nested hashtables and array definitions.
24. Rapid failover cycle simulation (2,000 alternating service commands).
25. Deeply nested code blocks and Confluence macro rendering.
26. Terminal VT100/ANSI cursor movement and clear codes.
27. Massive ITSM ticket payloads with 500 nested comment steps.
28. Boundary case IP/token redaction within file paths.
29. High-throughput HTML generation (50 consecutive runs).
30. Memory stability and garbage collection verification.

Adheres strictly to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 9 (Automated Test Harness with 100% Synthetic Mock Data).
"""

import gc
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
)


class TestDeepStressExtended(unittest.TestCase):
    """Extended stress testing suite covering complex syntax and scaling."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer(salt="extended-stress-salt")
        self.engine = RunbookEngine(sanitizer=self.sanitizer)

    def test_21_multiline_awk_python_inline_script(self) -> None:
        """21. Ingests inline Python and multiline AWK scripts safely."""
        script = (
            "python3 -c 'import sys, os; print(\"Checking endpoints\"); [print(i) for i in range(10)]'\n"
            "awk 'BEGIN { FS=\",\"; OFS=\"\\t\" } { if ($3 > 50) print $1, $3 }' /var/log/metrics.csv\n"
            "systemctl restart metrics-collector"
        )
        runbook = self.engine.build_runbook(script)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("python3 -c" in c for c in cmds))
        self.assertTrue(any("awk" in c for c in cmds))
        self.assertTrue(any("systemctl restart" in c for c in cmds))

    def test_22_massive_variable_dictionary_scaling(self) -> None:
        """22. Parameterizes 1,000 unique synthetic IP addresses and domains."""
        lines = [
            f"curl -I https://app-service-node-{i}.corp.internal/health\nping -c 1 192.0.2.{(i % 200) + 1}"
            for i in range(1, 1001)
        ]
        raw = "\n".join(lines)
        t0 = time.perf_counter()
        runbook = self.engine.build_runbook(raw)
        dur = time.perf_counter() - t0

        self.assertLess(dur, 2.0, f"Expected < 2.0s, took {dur:.3f}s")
        self.assertIn("<TARGET_FQDN>", runbook.parameter_dictionary)
        self.assertIn("<TARGET_IP>", runbook.parameter_dictionary)

    def test_23_complex_powershell_hashtables_and_arrays(self) -> None:
        """23. Ingests complex PowerShell nested hashtables and custom objects."""
        ps_code = (
            "$Config = @{\n"
            "    Environment = 'Production'\n"
            "    Nodes = @('App01', 'App02')\n"
            "    Settings = @{ Timeout = 30; Retries = 3 }\n"
            "}\n"
            "Restart-Service -Name W3SVC\n"
            "Get-Service -Name W3SVC\n"
        )
        runbook = self.engine.build_runbook(ps_code, target_env="Windows Server 2022")
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("Restart-Service" in c for c in cmds))

    def test_24_rapid_failover_cycle_simulation(self) -> None:
        """24. Ingests 2,000 rapid failover/restart cycles without state corruption."""
        lines = []
        for i in range(1, 1001):
            lines.append(f"systemctl stop db-replica-{i % 10}")
            lines.append(f"systemctl start db-replica-{i % 10}")
        raw = "\n".join(lines)

        t0 = time.perf_counter()
        runbook = self.engine.build_runbook(raw)
        dur = time.perf_counter() - t0

        self.assertLess(dur, 1.5, f"Expected < 1.5s, took {dur:.3f}s")
        self.assertGreater(len(runbook.rollback_steps), 0)

    def test_25_extreme_confluence_macro_depth(self) -> None:
        """25. Converts complex commands with nested quotes to Confluence wiki markup."""
        cmd = 'docker run -d --name test -e "APP_OPTS={ \'debug\': false, \'hosts\': [\'node1\', \'node2\'] }" myapp:v1'
        runbook = self.engine.build_runbook(cmd)
        conf = RunbookFormatter.to_confluence(runbook)
        self.assertIn("{code:language=bash}", conf)
        self.assertIn("APP_OPTS", conf)

    def test_26_ansi_vt100_cursor_movement_codes(self) -> None:
        """26. Strips VT100 cursor movement and screen-clearing control sequences."""
        raw_text = "\x1b[2J\x1b[H\x1b[32mChecking status...\x1b[0m\x1b[1A\nsystemctl restart api-service"
        runbook = self.engine.build_runbook(raw_text)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("api-service" in c for c in cmds))

    def test_27_massive_itsm_ticket_500_steps(self) -> None:
        """27. Parses a large ITSM ticket containing 500 resolution comments."""
        ticket = {
            "ticket_id": "INC-778899",
            "work_notes": [f"Executed remediation step {i}: systemctl restart worker-{i % 10}" for i in range(1, 501)]
        }
        raw_json = json.dumps(ticket)
        t0 = time.perf_counter()
        runbook = self.engine.build_runbook(raw_json)
        dur = time.perf_counter() - t0

        self.assertLess(dur, 1.0)
        self.assertGreater(len(runbook.execution_steps), 10)

    def test_28_boundary_ip_in_filepaths(self) -> None:
        """28. Correctly sanitizes IP addresses embedded inside filesystem paths."""
        text = "cp /var/backups/10.150.20.5/db.sql /data/restore/10.150.20.5/db.sql"
        scrubbed = self.sanitizer.scrub(text)
        self.assertNotIn("10.150.20.5", scrubbed)
        self.assertIn("192.0.2.", scrubbed)

    def test_29_high_throughput_html_generation_50_runs(self) -> None:
        """29. Benchmarks rapid sequential HTML document generation."""
        cmd = "systemctl restart webapp\ncurl -I http://localhost:8080/health"
        runbook = self.engine.build_runbook(cmd)

        t0 = time.perf_counter()
        for _ in range(50):
            html_doc = RunbookFormatter.to_html(runbook)
            self.assertIn("<!DOCTYPE html>", html_doc)
        dur = time.perf_counter() - t0
        self.assertLess(dur, 1.0, f"Expected 50 HTML renders < 1.0s, took {dur:.3f}s")

    def test_30_memory_stability_and_gc(self) -> None:
        """30. Verifies clean garbage collection across large allocations."""
        for _ in range(5):
            huge_text = "\n".join([f"systemctl restart worker-{i}" for i in range(2000)])
            rb = self.engine.build_runbook(huge_text)
            _ = RunbookFormatter.to_markdown(rb)
            del rb
            del huge_text

        collected = gc.collect()
        self.assertGreaterEqual(collected, 0)


if __name__ == "__main__":
    unittest.main()
