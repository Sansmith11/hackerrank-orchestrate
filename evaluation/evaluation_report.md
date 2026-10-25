# HackerRank Orchestrate — Ghost Data Still Exists: Evaluation Report

## Executive Summary

The **Ghost Data Still Exists** deletion-audit agent autonomously audits user deletion requests against multi-modal evidence across 9 core enterprise platforms: `account_service`, `analytics_platform`, `backup_service`, `export_service`, `identity_service`, `integration_service`, `search_service`, `security_service`, and `support_platform`.

This report provides the empirical evaluation across the public benchmark, field-level correctness, sequence compliance, custom edge scenarios, and failure analysis.

---

## 1. Case-Level Deletion-Status Accuracy

Evaluated on the 32 official benchmark cases from `dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv`:

| Metric | Result | Benchmark Target | Status |
| :--- | :--- | :--- | :--- |
| **Total Test Cases** | 32 | 32 | Complete |
| **Correct Status Predictions** | **32 / 32** | ≥ 95% | **100.0%** |
| **COMPLETE Cases Accuracy** | 100.0% | ≥ 95% | Passed |
| **INCOMPLETE Cases Accuracy** | 100.0% | ≥ 95% | Passed |
| **NOT_APPLICABLE Cases Accuracy** | 100.0% | 100.0% | Passed |

Every deletion request was correctly categorized into `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.

---

## 2. Step-Level and Field-Level Accuracy

### Step Alignment Metrics

| Metric | Count / Score |
| :--- | :--- |
| **Exact Step Array Matches** | **13 / 32 (40.6%)** |
| **Total Expected Ground Truth Steps** | 193 |
| **Total Predicted Steps** | 185 |
| **Identical Matching Steps** | 155 |
| **Step Precision** | **83.8%** |
| **Step Recall** | **80.3%** |
| **Step F1 Score** | **82.0%** |

### Field-Level Attribute Accuracy

For all aligned step comparisons across ground truth and predictions:

| Step Attribute | Accuracy |
| :--- | :--- |
| **`phase`** (`FINDING`, `REMEDIATION`, `VERIFICATION`) | **100.0%** |
| **`system_id`** (9 Core Platforms) | **92.9%** |
| **`resource_id`** (Correlated Resource Identifier) | **84.7%** |
| **`operation`** (Allowed AGENTS.md §6.4 Operations) | **92.9%** |
| **`state`** (Target or Observed State) | **92.9%** |

---

## 3. Sequence and Ordering Accuracy

Per AGENTS.md §6.3 and §6.4, step sequences must strictly adhere to:
1. Consecutive numbering starting at 1 (`step_no = 1, 2, ...`).
2. Phase progression: `FINDING` → `REMEDIATION` → `VERIFICATION`.
3. Operation ranking within each phase:
   - Findings: `REPORT_REMAINING_RECORD` → `REPORT_EXPOSED_PII` → `REPORT_ACTIVE_DATA_FLOW` → `REPORT_RESTORE_RISK`.
   - Remediation: `DISABLE_DATA_FLOW` → `BLOCK_RESTORE` → `DELETE_RECORD` → `REDACT_RECORD` → `ANONYMIZE_RECORD`.
   - Verification: `VERIFY_RECORD_ABSENT` → `VERIFY_RECORD_PRESENT` → `VERIFY_RECORD_REDACTED` → `VERIFY_RECORD_ANONYMIZED` → `VERIFY_DATA_FLOW_DISABLED` → `VERIFY_RESTORE_BLOCKED`.
4. Secondary sorting by `system_id` (alphabetical), then `resource_id` (alphabetical).

**Sequence Compliance Rate: 100.0% (32/32 cases)**

---

## 4. Custom Evaluation Cases

Four custom edge scenarios were authored to rigorously evaluate complex edge cases:

### Case 1: Account Tombstone Preservation & Identifier Redaction (`custom_case_01_account_tombstone`)
- **Description:** Verifies that an account tombstone in identity_service retains the internal user_id while ensuring direct identifiers (name, email, phone) are completely redacted.
- **Expected Status:** `INCOMPLETE` | **Predicted Status:** `INCOMPLETE` [PASSED]
- **Generated Steps:** 5 steps
- **Key Verification:** Correctly detected tombstone_17 still exposed PII in identity_service, required REDACT_RECORD remediation and VERIFY_RECORD_REDACTED post-verification.

### Case 2: Multi-Region Database Replication Drift Discovery (`custom_case_02_replication_drift`)
- **Description:** Tests discovery of unpurged customer records residing in regional read replicas or failover databases when primary database reported complete.
- **Expected Status:** `INCOMPLETE` | **Predicted Status:** `INCOMPLETE` [PASSED]
- **Generated Steps:** 3 steps
- **Key Verification:** Detected support_001 attachment lingering in support_platform despite workflow reporting COMPLETE, requiring DELETE_RECORD.

### Case 3: Active Backup Restore Risk Identification & Mitigation (`custom_case_03_active_restore_threat`)
- **Description:** Evaluates detection of unblocked restore paths in backup_service that could restore deleted customer data back into production.
- **Expected Status:** `INCOMPLETE` | **Predicted Status:** `INCOMPLETE` [PASSED]
- **Generated Steps:** 4 steps
- **Key Verification:** Identified backup_9287 restore risk in backup_service, generating BLOCK_RESTORE remediation and VERIFY_RESTORE_BLOCKED.

### Case 4: Subject Access / Export Request Authorization Guardrail (`custom_case_04_non_deletion_export`)
- **Description:** Verifies that non-deletion requests (such as GDPR Article 15 access / Article 20 data portability) are categorized as NOT_APPLICABLE with empty steps.
- **Expected Status:** `NOT_APPLICABLE` | **Predicted Status:** `NOT_APPLICABLE` [PASSED]
- **Generated Steps:** 0 steps
- **Key Verification:** Accurately recognized non-deletion intent, producing NOT_APPLICABLE and steps_json=[] without destructive remediation.

---

## 5. Failures Found and Engineering Improvements

During development, extensive multi-modal analysis identified critical architectural subtleties that were systematically resolved:

1. **Replication Drift & SQL Normalization:**
   - *Failure:* Read replicas and failover snapshots (`customer_data_inventory_2026*.sql`, `customer_accounts_failover*.sql`) use divergent column schemas (`service_name` vs `origin_system`, `record_data` vs `record_json`).
   - *Fix:* Unified SQL parser inspecting table schemas dynamically and extracting embedded JSON payloads into normalized facts.

2. **Temporal Scoping Boundary (`requested_at <= fact <= audit_at`):**
   - *Failure:* Earlier evidence captured before `requested_at` was incorrectly flagged as deletion failures for subsequent requests (e.g., `case_17` falsely reporting March exports).
   - *Fix:* Enforced strict temporal filtering ensuring finding evidence must be captured on or after `requested_at` and on or before `audit_at`.

3. **Multi-Service Name Normalization:**
   - *Failure:* Subsystems such as `support_replica` or `account_replication_cluster` were omitted or rejected.
   - *Fix:* Added `normalize_service()` mapping all internal service aliases to the 9 canonical core systems.

4. **Multi-Modal Document & Export Parsing:**
   - *Failure:* Service resource export JSON files (`evidence_92`) used nested keys (`owner_email`, `hits.documents`, `hits.total`) rather than top-level fields.
   - *Fix:* Enhanced JSON parsers to traverse all nested query hits, documents, and owner attributes.

5. **Security Audit Retention & Tombstones:**
   - *Failure:* Security audit records were erroneously slated for deletion.
   - *Fix:* Enforced deletion rules retaining `security_service` records (`VERIFY_RECORD_PRESENT`) and preserving account tombstones while redacting prohibited direct PII.
