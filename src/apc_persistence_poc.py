"""In-memory fault-injection PoC for APC cumulative-budget persistence.

The first save explicitly returns False.  A fresh BudgetState for the same
session then reloads the last successfully persisted value.  No external
service, network, or production data is touched.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1] / "alternatives" / "bounded_agents"
sys.path.insert(0, str(REPO))

from apc.approval import ApprovalStore  # noqa: E402
from apc.budget import BudgetState  # noqa: E402
from apc.calibrate import ImpactWeights  # noqa: E402
from apc.compose import CompositionChecker  # noqa: E402
from apc.core import (  # noqa: E402
    AuthorizationEnvelope, DelegationBudgetSpec, ExecutionRole, Principal, Scope,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction  # noqa: E402


class FailingOnceBackend:
    def __init__(self, fail_first: bool):
        self.fail_next = fail_first
        self.saved = {}
        self.save_results = []

    def load(self, session_id):
        state = self.saved.get(session_id)
        return dict(state) if state is not None else None

    def save(self, session_id, state):
        if self.fail_next:
            self.fail_next = False
            self.save_results.append(False)
            return False
        self.saved[session_id] = dict(state)
        self.save_results.append(True)
        return True


def run_case(fail_first: bool):
    key = b"persistence-reproduction-key"
    scope = Scope(
        frozenset({"docs:public-demo"}), frozenset({"read"}), frozenset({"public"})
    )
    spec = DelegationBudgetSpec(2, 1.0, 5, "public", True, 1.0)
    owner = Principal("user:owner", ExecutionRole.AS_USER, scope)
    envelope = AuthorizationEnvelope(
        envelope_id="budget-root", task_session_id="same-session",
        originating_principal=owner, effective_scope=scope, budget_spec=spec,
    )
    envelope.sign(key)
    backend = FailingOnceBackend(fail_first)
    pdp = PolicyDecisionPoint(
        signing_key=key,
        impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )
    decisions = []
    for attempt in (1, 2):
        # This models a process restart while the session and signed grant live.
        state = BudgetState.from_backend(spec, "same-session", backend)
        before = state.snapshot()
        action = ProposedAction(
            action_type="read", target_resource="docs:public-demo",
            parameters={"attempt": attempt}, actor_principal_id=owner.principal_id,
            task_session_id="same-session", policy_version="1.0",
            sensitivity_class="public", compute_cost=0.6,
        )
        result = pdp.evaluate(
            action, envelope, state,
            CompositionChecker(restrictions=frozenset()),
        )
        decisions.append({
            "attempt": attempt,
            "loaded_cost_before": before["cumulative_cost"],
            "admitted": result.admitted,
            "denial_reasons": result.denial_reasons,
            "state_cost_after": state.cumulative_cost,
            "persisted_cost_after": backend.load("same-session")["cumulative_cost"]
            if backend.load("same-session") is not None else None,
        })
    return {
        "fail_first_save": fail_first,
        "max_cost": spec.max_cost,
        "cost_per_action": 0.6,
        "envelope_signature_valid": envelope.verify(key),
        "save_results": backend.save_results,
        "decisions": decisions,
        "total_admitted_cost": sum(0.6 for x in decisions if x["admitted"]),
    }


def run():
    failed = run_case(True)
    normal = run_case(False)
    checks = {
        "failed_first_write_acknowledged": failed["save_results"] == [False, True],
        "failed_write_still_admitted": failed["decisions"][0]["admitted"],
        "same_session_second_action_admitted": failed["decisions"][1]["admitted"],
        "failed_case_exceeds_cap": failed["total_admitted_cost"] > failed["max_cost"],
        "normal_first_admitted": normal["decisions"][0]["admitted"],
        "normal_second_denied": not normal["decisions"][1]["admitted"],
        "normal_case_stays_within_cap": normal["total_admitted_cost"] <= normal["max_cost"],
    }
    assert all(checks.values()), json.dumps({"failed": failed, "normal": normal}, indent=2)
    return {
        "repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "failed_save": failed,
        "normal_save_control": normal,
        "checks": checks,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
