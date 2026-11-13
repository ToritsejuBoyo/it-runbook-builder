---
name: it-runbook-builder
description: >-
  Converts raw terminal command histories (Bash, Zsh, PowerShell), ITSM ticket work notes
  (ServiceNow, Jira), and incident bridge chat logs into standardized, audit-ready IT Runbooks and
  Standard Operating Procedures (SOPs) with automated pre-flight checks, parameterized variables,
  verification steps, and client-side secret/PII sanitization. Use this skill when an engineer or
  team needs to eliminate tribal knowledge, document an incident resolution, create a change
  management runbook, or produce a clean SOP.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# IT Infrastructure Runbook & SOP Builder (`it-runbook-builder`)

## Overview

Documentation debt and unrecorded tribal knowledge impact every IT operations team, MSP, and SRE organization. When senior engineers resolve critical production outages at 2:00 AM, the fix remains trapped in terminal scrollback, bash history files, or chaotic incident chat threads. When the incident recurs, junior staff spend hours reinventing the resolution or execute partial fixes that cause cascading outages.

This skill provides an automated, zero-dependency documentation synthesis engine (`scripts/runbook_builder.py`) that ingests raw operational telemetry, strips sensitive credentials and internal IPs client-side, filters out interactive noise commands (`cd`, `ls`, `clear`), and structures the workflow into the 8 mandatory ITIL/SOC 2 runbook sections:
1. **Document Metadata & Scope** (Owner, Runbook ID, Review Cadence, Estimated Time)
2. **Variable & Parameter Dictionary** (`<TARGET_FQDN>`, `<TARGET_IP>`, `<SERVICE_NAME>`)
3. **Prerequisites & RBAC Privileges** (Required administrative access and network paths)
4. **Pre-Flight Health Checks** (Read-only state assertions before making changes)
5. **Step-by-Step Procedure** (Numbered instructions with copy-paste commands and expected outputs)
6. **Post-Execution Verification** (Explicit validation commands to prove success)
7. **Mandatory Rollback & Backout Plan** (Reverse chronological recovery sequence)
8. **Troubleshooting & Common Failure Modes** (Symptom-cause-remediation matrix)

---

## Operating Rules & Safety Guardrails

1. **Strictly Read-Only Offline Execution (Rule 3):**
   - The analysis and synthesis engine operates entirely offline on static text, transcripts, or JSON ticket dumps.
   - Never initiate live network connections or execute mutating commands against target systems.
2. **Client-Side Secret & PII Scrubbing (Rule 4):**
   - When `--sanitize` is active (default), the engine automatically redacts passwords (`-p <SECRET>`, `--password <SECRET>`), bearer tokens (`Bearer [REDACTED_BEARER_TOKEN]`), AWS access keys (`AKIA...`), SSH private keys, private IPv4 addresses (`10.x`, `172.16-31.x`, `192.168.x`), internal domains (`*.corp.internal`), and user emails.
   - Guarantees zero sensitive customer telemetry touches an external LLM or leaves the workstation.
3. **Deterministic Structure & Reversibility:**
   - Every procedure must pair state-changing commands with immediate verification assertions.
   - A backout/rollback plan is mandatory for every state change.
4. **Zero-Emoji Enterprise Tone (Rule 7):**
   - Generates authoritative, clean markdown, HTML, and Confluence wiki documentation without informal emojis or casual chat slang.

---

## Telemetry Ingestion & Usage

### Mode A: Automated CLI Engine (Recommended)

Run the zero-dependency Python script directly against your command history or ticket notes:

```bash
# Convert Bash / Linux command history to standard Markdown Runbook
python scripts/runbook_builder.py \
  --input ./history.txt \
  --title "Standard Operating Procedure: Production Nginx SSL Renewal" \
  --environment "Production Linux" \
  --format markdown \
  --sanitize \
  --output ./runbook-ssl-renewal.md

# Convert PowerShell transcript to Atlassian Confluence wiki markup
python scripts/runbook_builder.py \
  --input ./PowerShell_transcript.txt \
  --title "SOP: IIS Application Pool Remediation" \
  --environment "Windows Server 2022" \
  --format confluence \
  --sanitize \
  --output ./iis-runbook-confluence.txt

# Ingest Jira/ServiceNow ticket JSON and generate standalone responsive HTML
python scripts/runbook_builder.py \
  --input ./jira-ticket-notes.json \
  --format html \
  --sanitize \
  --output ./runbook-report.html

# Generate a sanitized SRE Portfolio Case Study (Proof-of-Work)
python scripts/runbook_builder.py \
  --input ./history.txt \
  --generate-proof-of-work \
  --sanitize \
  --output ./case-study.md
```

### Mode B: Direct Text / Snippet Paste

If executing inside an interactive LLM session, paste the raw terminal history, PowerShell commands, or ticket work notes directly into the conversation. The agent parses the commands, parameterizes environment variables, and generates the complete 8-section runbook.

---

## Runbook Structural Lifecycle

```
┌────────────────────────────────────────────────────────┐
│             1. Raw Input Ingestion                     │
│   (Bash History, PowerShell Transcripts, Ticket Notes) │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             2. Telemetry Cleaning & Scrubbing          │
│   - Redact passwords, bearer tokens, AWS keys, and IPs │
│   - Filter interactive noise commands (cd, ls, clear)  │
│   - Parameterize variables (<TARGET_HOST>, <PORT>)     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             3. Structural Synthesis (ITIL / SOC 2)     │
│   - Derive prerequisites & RBAC permissions            │
│   - Identify pre-flight read-only checks               │
│   - Sequence numbered execution steps                  │
│   - Pair each step with verification command           │
│   - Synthesize reverse-order rollback procedure        │
│   - Compile troubleshooting & failure mode matrix      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             4. Multi-Format Output Generation          │
│   (Markdown, Confluence Wiki, Standalone HTML, JSON)   │
└────────────────────────────────────────────────────────┘
```

---

## Bundled Tools & Resources

- **Core Synthesis Engine:** [`scripts/runbook_builder.py`](scripts/runbook_builder.py) — Zero-dependency Python CLI tool that parses, scrubs, and renders runbooks.
- **Sanitization Helper:** [`scripts/sanitize_session_history.py`](scripts/sanitize_session_history.py) — Standalone pre-pass that scrubs secrets and PII from a raw shell history before it is fed to the synthesis engine. Use when the operator wants to sanitize input separately from runbook generation.
- **ITIL & SOC 2 Standards Guide:** [`references/itil-runbook-standards.md`](references/itil-runbook-standards.md) — Comprehensive technical reference on governance requirements, command parameterization, and rollback engineering.
- **Runbook Standard Rubric:** [`references/runbook-standard-rubric.md`](references/runbook-standard-rubric.md) — The required-sections rubric every generated runbook is graded against. **Consult before finalizing any runbook.**
- **Enterprise Runbook Template:** [`assets/enterprise-runbook-template.md`](assets/enterprise-runbook-template.md) — Standard Operating Procedure template with document ID, pre-flight, verification, and rollback blocks.
- **Proof-of-Work Case Study Template:** [`assets/proof-of-work-case-study-template.md`](assets/proof-of-work-case-study-template.md) — Portfolio write-up template for presenting a completed runbook as technical proof-of-work.
- **Automated Test Suites:**
  - Standard Test Harness: [`tests/validate-skill.py`](tests/validate-skill.py)
  - High-Volume Throughput Benchmark: [`tests/stress_test_runbook_builder.py`](tests/stress_test_runbook_builder.py)
  - Extreme Edge Cases & Malformed Payloads: [`tests/extreme_test_runbook_builder.py`](tests/extreme_test_runbook_builder.py)

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
