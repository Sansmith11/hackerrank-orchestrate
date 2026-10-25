"""Policy and Step Ordering Definitions for Ghost Data Still Exists Deletion Audit Agent.

Strictly follows Section 6.3, 6.4, and 6.5 of AGENTS.md.
"""

from typing import List, Dict, Any

# Operation priority order within each phase as defined in AGENTS.md section 6.4
PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3
}

FINDING_OP_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4
}

REMEDIATION_OP_ORDER = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5
}

VERIFICATION_OP_ORDER = {
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6
}

OP_ORDER_BY_PHASE = {
    "FINDING": FINDING_OP_ORDER,
    "REMEDIATION": REMEDIATION_OP_ORDER,
    "VERIFICATION": VERIFICATION_OP_ORDER
}

# Mapping of finding operation to corresponding remediation operation and verification operation
FINDING_TO_REMEDIATION = {
    "REPORT_REMAINING_RECORD": "DELETE_RECORD",
    "REPORT_EXPOSED_PII": "REDACT_RECORD",       # Default for support messages and tombstones
    "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE"
}

REMEDIATION_TO_STATE = {
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED"
}

VERIFICATION_TO_STATE = {
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED"
}


def sort_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sorts steps strictly by:

    1. Phase (FINDING -> REMEDIATION -> VERIFICATION)
    2. Operation order within phase (as defined in challenge table)
    3. System ID ascending
    4. Resource ID ascending
    Assigns consecutive step_no starting from 1.
    """
    def step_key(s: Dict[str, Any]):
        phase = s.get("phase", "")
        phase_rank = PHASE_ORDER.get(phase, 99)

        op = s.get("operation", "")
        op_rank_dict = OP_ORDER_BY_PHASE.get(phase, {})
        op_rank = op_rank_dict.get(op, 99)

        system_id = s.get("system_id", "")
        resource_id = s.get("resource_id", "")

        return (phase_rank, op_rank, system_id, resource_id)

    sorted_list = sorted(steps, key=step_key)

    # Renumber consecutively starting from 1
    final_steps = []
    for i, st in enumerate(sorted_list, start=1):
        item = {
            "step_no": i,
            "phase": st["phase"],
            "system_id": st["system_id"],
            "resource_id": st["resource_id"],
            "operation": st["operation"],
            "state": st["state"],
            "evidence_id": st.get("evidence_id", "")
        }
        final_steps.append(item)

    return final_steps
