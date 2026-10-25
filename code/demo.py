"""Interactive Live Demo of Ghost Data Still Exists Deletion Audit Agent.

Demonstrates:
1. COMPLETE Case: Evidence-backed verification proving compliant deletion state at audit_at.
2. INCOMPLETE Case: Detection of ghost data, recreation risks, ordered remediation plan, and verification.
3. NOT_APPLICABLE Case: Guardrail recognizing non-deletion intents (access, correction, export).
"""

import csv
import json
import os
import sys

# Windows utf-8 support
sys.stdout.reconfigure(encoding='utf-8')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DATASET_DIR = os.path.join(REPO_ROOT, "dataset")

if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from audit_agent import DeletionAuditAgent


def print_banner(text: str):
    print("\n" + "=" * 80)
    print(f" {text}")
    print("=" * 80)


def print_case_demo(agent: DeletionAuditAgent, case_dict: dict, label: str):
    cid = case_dict["case_id"]
    email = case_dict["email"]
    req_at = case_dict["requested_at"]
    rep_status = case_dict["reported_status"]
    rep_at = case_dict["reported_at"]
    audit_at = case_dict["audit_at"]
    req_text = case_dict["request_text"]

    print_banner(f"DEMO SCENARIO: {label} (Case ID: {cid})")
    print(f"* Subject Email:      {email}")
    print(f"* Request Text:       \"{req_text}\"")
    print(f"* Requested At:       {req_at}")
    print(f"* Workflow Claim:     {rep_status} (Reported at {rep_at})")
    print(f"* Audit Cutoff Time:  {audit_at}")

    # 1. Identity Resolution
    user = agent.resolver.resolve_by_email(email)
    if user:
        print(f"\n[Identity Resolver]")
        print(f"  - Stable User ID:   {user['user_id']}")
        print(f"  - Primary Name:     {user['primary_name']}")
        print(f"  - Associated Emails:{list(user['emails'])}")
        print(f"  - Associated Phones:{list(user['phones'])}")
    else:
        print("\n[Identity Resolver] User identity could not be resolved.")

    # 2. Audit Case
    status, steps = agent.audit_case(case_dict)

    print(f"\n[Audit Agent Decision]")
    print(f"  -> Final Deletion Status: {status}")
    print(f"  -> Total Steps Generated: {len(steps)}")

    if steps:
        print(f"\n[Steps Breakdown: FINDING -> REMEDIATION -> VERIFICATION]")
        print(f"  {'#':<3} | {'Phase':<12} | {'System':<20} | {'Resource':<18} | {'Operation':<26} | {'State':<10} | {'Evidence'}")
        print("  " + "-" * 105)
        for s in steps:
            ev = s.get("evidence_id") or "(future check)"
            print(f"  {s['step_no']:<3} | {s['phase']:<12} | {s['system_id']:<20} | {s['resource_id']:<18} | {s['operation']:<26} | {s['state']:<10} | {ev}")
    else:
        print("  (Empty steps array [] as required for non-deletion / non-applicable requests)")


def main():
    print("=" * 80)
    print(" GHOST DATA STILL EXISTS: LIVE DELETION-AUDIT AGENT DEMO")
    print("=" * 80)

    print("\nInitializing Agent, Multi-Modal Evidence Engine, and Identity Resolver...")
    agent = DeletionAuditAgent(DATASET_DIR)
    print(f"Ready! Engine loaded {len(agent.engine.facts)} facts across 9 core enterprise platforms.")

    # Load samples
    sample_path = os.path.join(DATASET_DIR, "sample_deletion_requests.csv")
    with open(sample_path, "r", encoding="utf-8") as f:
        samples = {r["case_id"]: r for r in csv.DictReader(f)}

    # Demo 1: COMPLETE Case (case_01)
    if "case_01" in samples:
        print_case_demo(agent, samples["case_01"], "Verified Complete Deletion")

    # Demo 2: INCOMPLETE Case with Ghost Records and Risks (case_11)
    if "case_11" in samples:
        print_case_demo(agent, samples["case_11"], "Ghost Data Still Exists (Incomplete Deletion)")

    # Demo 3: NOT_APPLICABLE Case (Non-Deletion Request)
    not_app_case = {
        "case_id": "demo_non_deletion_case",
        "email": "sarah.jenkins@example.com",
        "requested_at": "2026-08-10T12:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-08-11T12:00:00Z",
        "audit_at": "2026-08-15T12:00:00Z",
        "request_text": "Please provide me with a downloadable copy of last year's invoices. I am not asking for deletion."
    }
    print_case_demo(agent, not_app_case, "Non-Deletion Data Access / Portability Request")

    print_banner("DEMO SUMMARY")
    print("The agent successfully demonstrated:")
    print(" 1. Grounded evidence verification on COMPLETE cases.")
    print(" 2. Multi-modal ghost data detection, ordered remediation, and verification on INCOMPLETE cases.")
    print(" 3. Safe authorization guardrails preventing accidental erasure on NOT_APPLICABLE cases.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
