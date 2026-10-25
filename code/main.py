"""Main entry point for Ghost Data Still Exists deletion audit agent.

Audits all 518 evaluation deletion requests in dataset/deletion_requests.csv
and outputs the canonical predictions to output.csv at the repository root.
"""

import csv
import json
import os
import sys
import time

# Ensure code directory is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from audit_agent import DeletionAuditAgent


def main():
    start_time = time.time()
    print("=" * 60)
    print("HackerRank Orchestrate - Ghost Data Still Exists: Deletion Audit Agent")
    print("=" * 60)

    # Resolve paths relative to repository root
    repo_root = os.path.dirname(SCRIPT_DIR)
    dataset_dir = os.path.join(repo_root, "dataset")
    eval_requests_path = os.path.join(dataset_dir, "deletion_requests.csv")
    output_csv_path = os.path.join(repo_root, "output.csv")

    print(f"Repository Root: {repo_root}")
    print(f"Dataset Directory: {dataset_dir}")
    print(f"Evaluation Requests: {eval_requests_path}")
    print(f"Target Output Path: {output_csv_path}")

    if not os.path.exists(eval_requests_path):
        print(f"Error: Evaluation requests file not found at {eval_requests_path}")
        sys.exit(1)

    print("\n[1/3] Initializing Identity Resolver & Multi-modal Evidence Engine...")
    agent = DeletionAuditAgent(dataset_dir)
    print(f"  - Loaded {len(agent.engine.facts)} evidence facts across 9 core systems.")
    print(f"  - Mapped {len(agent.user_audit_records)} security audit records.")
    print(f"  - Indexed system activity workflows across dates.")

    print("\n[2/3] Auditing 518 evaluation requests...")
    with open(eval_requests_path, "r", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    print(f"  - Found {len(requests)} requests to audit.")

    # Sort requests by case_id
    requests.sort(key=lambda r: r["case_id"])

    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    results = []

    for idx, req in enumerate(requests, 1):
        cid = req["case_id"]
        status, steps = agent.audit_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1

        steps_json = json.dumps(steps, separators=(',', ':'))
        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_json
        })

        if idx % 100 == 0 or idx == len(requests):
            print(f"  - Audited {idx}/{len(requests)} cases...")

    print("\n[3/3] Writing canonical output.csv...")
    with open(output_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print(f"Audit completed successfully in {elapsed:.2f} seconds.")
    print(f"Summary of Decisions across {len(results)} cases:")
    print(f"  - COMPLETE:       {status_counts.get('COMPLETE', 0):>4} ({status_counts.get('COMPLETE', 0)/len(results)*100:.1f}%)")
    print(f"  - INCOMPLETE:     {status_counts.get('INCOMPLETE', 0):>4} ({status_counts.get('INCOMPLETE', 0)/len(results)*100:.1f}%)")
    print(f"  - NOT_APPLICABLE: {status_counts.get('NOT_APPLICABLE', 0):>4} ({status_counts.get('NOT_APPLICABLE', 0)/len(results)*100:.1f}%)")
    print(f"Output saved to: {output_csv_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
