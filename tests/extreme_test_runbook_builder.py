#!/usr/bin/env python3
"""
Extreme Edge Cases & Malformed Payload Test Suite: it-runbook-builder

Tests resilience against malformed ticket JSON, empty inputs, ReDoS attacks,
zero-width Unicode injection, single-line heredocs, and hostile payloads.

Adheres strictly to Workspace Rule 7 (Zero-Emoji Enterprise Tone) and
Rule 9 (Automated Test Harness with 100% Synthetic Mock Data).
"""

import os
import sys
import tempfile
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


class TestExtremeEdgeCases(unittest.TestCase):
    """Extreme edge case verification for runbook synthesis."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer(salt="extreme-salt")
        self.engine = RunbookEngine(sanitizer=self.sanitizer)

    def test_empty_input_and_whitespace(self) -> None:
        """Handles empty string or pure whitespace without crashing."""
        runbook = self.engine.build_runbook("   \n\t\n   ")
        self.assertEqual(len(runbook.execution_steps), 0)
        markdown = RunbookFormatter.to_markdown(runbook)
        self.assertIn("Overview & Purpose", markdown)
        json_out = RunbookFormatter.to_json(runbook)
        self.assertIn("metadata", json_out)

    def test_corrupted_json_ticket_handling(self) -> None:
        """Recovers gracefully when JSON ticket payload is truncated or invalid."""
        corrupted_json = '{"issue_key": "INC-1234", "work_notes": ["apt update", "apt upgrade"'
        runbook = self.engine.build_runbook(corrupted_json)
        # Should fall back to raw text parsing and extract available commands
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("apt" in c for c in cmds))

    def test_redos_pattern_resilience(self) -> None:
        """Guards against catastrophic backtracking on pathological IP and secret patterns."""
        pathological_ip = "192.168." * 3000 + "999"
        scrubbed = self.sanitizer.scrub(pathological_ip)
        self.assertTrue(len(scrubbed) > 0)

        pathological_bearer = "Bearer " + ("a" * 10000)
        scrubbed_bearer = self.sanitizer.scrub(pathological_bearer)
        self.assertIn("[REDACTED_BEARER_TOKEN]", scrubbed_bearer)

    def test_unicode_and_zero_width_injection(self) -> None:
        """Strips zero-width characters, bidirectional overrides, and informal emojis."""
        hostile_text = "systemctl restart \u200b\u200capp-service\ufeff\u202e \U0001F525\U0001F680"
        scrubbed = self.sanitizer.scrub(hostile_text)
        self.assertNotIn("\u200b", scrubbed)
        self.assertNotIn("\ufeff", scrubbed)
        self.assertNotIn("\U0001F525", scrubbed)
        self.assertIn("app-service", scrubbed)

    def test_heredoc_multiline_command_parsing(self) -> None:
        """Parses multiline script containing heredoc definitions."""
        heredoc_text = """
cat << 'EOF' > /etc/systemd/system/myapp.service
[Unit]
Description=My App Service
After=network.target

[Service]
ExecStart=/usr/bin/myapp
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now myapp
"""
        runbook = self.engine.build_runbook(heredoc_text)
        cmds = [s.command for s in runbook.execution_steps]
        self.assertTrue(any("systemctl daemon-reload" in c for c in cmds))
        self.assertTrue(any("systemctl enable" in c for c in cmds))

    def test_pipes_and_command_chaining(self) -> None:
        """Preserves pipe chains and conditional execution operators."""
        chain_cmd = "docker build -t myapp:latest . && docker push myapp:latest || echo 'Build failed'"
        runbook = self.engine.build_runbook(chain_cmd)
        self.assertEqual(len(runbook.execution_steps), 1)
        self.assertEqual(runbook.execution_steps[0].command, chain_cmd)

    def test_extremely_long_single_command_line(self) -> None:
        """Handles 50,000-character command line with hundreds of parameters without crash."""
        massive_cmd = "python app.py " + " ".join([f"--param-{i}=value-{i}" for i in range(1000)])
        runbook = self.engine.build_runbook(massive_cmd)
        self.assertEqual(len(runbook.execution_steps), 1)
        self.assertGreater(len(runbook.execution_steps[0].command), 10000)

    def test_all_noise_commands_fallback(self) -> None:
        """Ensures input with only noise commands (ls, cd, pwd, clear) generates baseline runbook."""
        noise_input = "cd /var/log\nls -la\npwd\nclear\nwhoami\n"
        runbook = self.engine.build_runbook(noise_input)
        self.assertEqual(len(runbook.execution_steps), 0)
        self.assertGreaterEqual(len(runbook.verification_steps), 1)
        self.assertGreaterEqual(len(runbook.rollback_steps), 1)


if __name__ == "__main__":
    unittest.main()
