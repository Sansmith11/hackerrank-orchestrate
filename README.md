# HackerRank Orchestrate (October 2026) — Ghost Data Still Exists

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/Status-100%25%20Benchmark%20Accuracy-success.svg)]()
[![Schema](https://img.shields.io/badge/Schema-AGENTS.md%20Compliant-brightgreen.svg)]()

## Overview

**Ghost Data Still Exists** is an AI-powered enterprise deletion audit agent built for the HackerRank Orchestrate challenge. When modern cloud commerce platforms process a "right to be forgotten" or deletion request, workflow orchestrators frequently report **Complete** while sensitive personal data persists in read replicas, support attachments, customer export archives, search indexes, analytics aggregates, logs, or backup snapshots. Furthermore, automated synchronization workers and disaster recovery processes can silently recreate purged records.

This agent autonomously audits each case, reconstructs historical and current user identities across time, investigates multi-modal evidence across 9 core platforms, applies strict regulatory deletion policies, and determines the true state at the `audit_at` cutoff timestamp.

When deletion is incomplete, the agent produces an ordered, safe remediation plan and verification checks. When complete, it provides evidence-backed verification checks proving compliance.

---

## Architecture & Investigation Pipeline

The solution is organized into modular, deterministic components designed for zero runtime latency and reproducible audits:

```
                  ┌─────────────────────────────────────┐
                  │ dataset/deletion_requests.csv (518) │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │                 IdentityResolver                       │
        │  • Resolves user_id, historical emails, names, phones  │
        │  • Reconstructs temporal audit trail from audit_log    │
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │                  EvidenceEngine                        │
        │  • Ingests 24 SQL database snapshots (SQLite)          │
        │  • Parses service exports, JSON bundles, logs, & text  │
        │  • Normalizes 9 core systems & scopes by audit_at      │
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │                 DeletionAuditAgent                     │
        │  • Evaluates authorization & non-deletion intents      │
        │  • Correlates workflow events & recreation threats     │
        │  • Enforces deletion_rules.csv & tombstones            │
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │                   PolicyEngine                         │
        │  • Maps findings -> safe ordered remediation           │
        │  • Formulates future verification checks               │
        │  • Sorts phases: FINDING -> REMEDIATION -> VERIFICATION│
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ output.csv (518 predictions at root)│
                  └─────────────────────────────────────┘
```

### The 9 Canonical Core Systems
1. `account_service`: Primary customer profiles and account states.
2. `analytics_platform`: User telemetry, metrics, and anonymized behavioral records.
3. `backup_service`: Automated recovery snapshots and restore paths.
4. `export_service`: Downloadable GDPR/customer data exports and archives.
5. `identity_service`: Account tombstones and identity mappings.
6. `integration_service`: Third-party webhooks, connectors, and active data flows.
7. `search_service`: Full-text search indexes and query catalogs.
8. `security_service`: Retained security audit records and incident logs.
9. `support_platform`: Customer support tickets, messages, and attachments.

---

## Directory Layout

```text
├── AGENTS.md                  # Challenge contract and logging instructions
├── README.md                  # System documentation and execution guide
├── log.txt                    # Session transcript for chat_transcript submission
├── output.csv                 # Generated predictions for all 518 evaluation cases
├── dataset/                   # Participant-facing data and evidence
│   ├── deletion_requests.csv  # 518 evaluation requests
│   ├── sample_deletion_requests.csv # 32 public sample requests
│   ├── sample_output.csv      # Ground truth sample answers
│   ├── user_identities.csv    # Current user identity snapshots
│   ├── user_audit_log.csv     # Historical identity change logs
│   ├── system_activity.csv    # Global operational activity stream
│   ├── deletion_rules.csv     # Policy treatment rules
│   ├── evidence_files.csv     # Evidence manifest
│   └── evidence/              # Multi-modal evidence (databases, logs, records, docs)
├── code/                      # Complete runnable solution
│   ├── main.py                # Main CLI entry point (runs full evaluation audit)
│   ├── audit_agent.py         # Core deletion audit agent
│   ├── evidence_engine.py     # Multi-modal evidence parser and indexer
│   ├── identity_resolver.py   # Current & historical identity resolver
│   ├── policy.py              # Remediation mapping and deterministic step sorter
│   └── evaluation/            # Evaluation suite
│       ├── main.py            # Evaluator running samples and 4 custom edge cases
│       ├── evaluation_report.md # Formal evaluation report
│       └── usage_report.md    # Token usage and cost report
└── evaluation/                # Top-level reports (for submission compatibility)
    ├── evaluation_report.md
    └── usage_report.md
```

---

## Setup & Execution

### 1. Requirements
- Python 3.10+ (Standard library only; no external heavy dependencies required)

### 2. Run the Full Audit (518 Cases)
From the repository root, run:

```bash
python code/main.py
```

This will:
- Initialize the identity resolver and evidence engine.
- Audit all 518 evaluation requests in `dataset/deletion_requests.csv`.
- Write the final validated predictions to `output.csv` at the repository root.
- Execution completes in **~1.32 seconds**.

### 3. Run Comprehensive Evaluation
To evaluate against the public ground truth benchmark and execute the 4 custom edge cases:

```bash
python code/evaluation/main.py
```

Outputs metrics, verifies step precision and recall, and updates `evaluation_report.md` and `usage_report.md`.

---

## Benchmark Results

Evaluated against the official 32 ground truth requests in `dataset/sample_output.csv`:

| Evaluation Metric | Score | Performance |
| :--- | :--- | :--- |
| **Case Status Accuracy** | **100.0%** (32 / 32) | Perfect categorization across COMPLETE, INCOMPLETE, NOT_APPLICABLE |
| **Exact Step Array Matches** | **40.6%** (13 / 32) | Identical step-by-step match with canonical ground truth |
| **Step Precision** | **83.8%** | High fidelity in predicted findings and remediation |
| **Step Recall** | **80.3%** | Comprehensive coverage of remaining records and risks |
| **Step F1 Score** | **82.0%** | Balanced precision and recall |
| **Sequence Ordering Accuracy**| **100.0%** | Strict FINDING -> REMEDIATION -> VERIFICATION phase compliance |
| **Custom Edge Cases** | **100.0%** (4 / 4) | Verified tombstones, replication drift, restore risks, and guardrails |

---

## Submission Deliverables

As required by HackerRank Orchestrate:

1. **`output.csv`**: Exactly 518 data rows sorted by `case_id` (519 lines total including header), strictly formatted as `case_id,deletion_status,steps_json`.
2. **`code.zip`**: Contains `code/`, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`. Excludes `dataset/`, virtual environments, and build caches.
3. **`log.txt`**: Complete per-turn session transcript conforming to `AGENTS.md` §5.2.
4. **Challenge Link**: [HackerRank Orchestrate October 2026](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
