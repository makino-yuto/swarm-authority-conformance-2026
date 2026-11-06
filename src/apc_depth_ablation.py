"""Paired ablation of bounded-agents' published depth-overflow evaluation.

Imports the unmodified reference implementation at the pinned local commit.
All principals, resources, and decisions exist in memory only.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1] / "alternatives" / "bounded_agents"
sys.path.insert(0, str(REPO))

from apc.approval import ApprovalStore  # noqa: E402
from apc.budget import ActionCost, BudgetState  # noqa: E402
from apc.calibrate import ImpactWeights  # noqa: E402
from apc.compose import CompositionChecker  # noqa: E402
from apc.core import (  # noqa: E402
    AuthorizationEnvelope, DelegationBudgetSpec, ExecutionRole, Principal, Scope,
)
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction  # noqa: E402
from evals.adaptive.run_adaptive import attack_depth_overflow  # noqa: E402

KEY = b"adaptive-benchmark-key"


def make_envelopes():
    scope = Scope(frozenset({"docs:*"}), frozenset({"read"}), frozenset({"public"}))
    spec = DelegationBudgetSpec(2, 1.0, 5, "public", False, 10.0)
    owner = Principal("user:alice", ExecutionRole.AS_USER, scope)
    root = AuthorizationEnvelope(
        envelope_id="env-depth", task_session_id="session-depth",
        originating_principal=owner, effective_scope=scope,
        budget_spec=spec, expires_at=time.time() + 3600,
    )
    root.sign(KEY)
    chain = [root]
    for hop in range(1, 4):
        agent = Principal(f"agent:hop-{hop}", ExecutionRole.AS_AGENT, scope)
        chain.append(chain[-1].narrow(agent, KEY))
    return chain, spec


def evaluate(envelope, spec, preconsume_irreversible: int, action_irreversible: int):
    pdp = PolicyDecisionPoint(
        signing_key=KEY,
        impact_weights=ImpactWeights(0.4, 0.35, 0.25),
        approval_threshold=0.5,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )
    state = BudgetState(spec=spec)
    assert state.consume(ActionCost(delegation_hops=2)).allowed
    if preconsume_irreversible:
        assert state.consume(ActionCost(irreversible_effects=preconsume_irreversible)).allowed
    before = state.snapshot()
    action = ProposedAction(
        action_type="read", target_resource="docs:file.txt", parameters={},
        actor_principal_id=envelope.chain[-1].principal_id,
        task_session_id="session-depth", policy_version="1.0",
        sensitivity_class="public", irreversible_effects=action_irreversible,
    )
    result = pdp.evaluate(
        action, envelope, state,
        CompositionChecker(restrictions=frozenset()),
    )
    return {
        "envelope_depth": envelope.delegation_depth,
        "signed_depth_cap": envelope.budget_spec.max_delegation_depth,
        "signature_valid": envelope.verify(KEY),
        "budget_before": before,
        "action_irreversible_effects": action_irreversible,
        "admitted": result.admitted,
        "denial_reasons": result.denial_reasons,
        "conditions": {name: entry.passed for name, entry in result.condition_results.items()},
        "budget_after": state.snapshot(),
    }


def run():
    chain, spec = make_envelopes()
    upstream = [
        {"name": r.name, "blocked": r.blocked, "reason": r.reason}
        for r in attack_depth_overflow()
    ]
    cases = {
        "legal_depth_control": evaluate(chain[2], spec, 0, 1),
        "legal_depth_with_irreversible_preload": evaluate(chain[2], spec, 5, 1),
        "published_confound": evaluate(chain[3], spec, 5, 1),
        "remove_irreversible_preload": evaluate(chain[3], spec, 0, 1),
        "remove_irreversible_action_cost": evaluate(chain[3], spec, 5, 0),
    }
    checks = {
        "upstream_reports_overflow_blocked": upstream[-1]["blocked"],
        "published_confound_denies": not cases["published_confound"]["admitted"],
        "published_denial_is_irreversible_not_depth": any(
            "irreversible_effects" in reason
            for reason in cases["published_confound"]["denial_reasons"]
        ),
        "legal_depth_also_denied_by_preload": not cases[
            "legal_depth_with_irreversible_preload"
        ]["admitted"],
        "remove_preload_admits_depth_three": cases["remove_irreversible_preload"]["admitted"],
        "remove_action_cost_admits_depth_three": cases["remove_irreversible_action_cost"]["admitted"],
        "depth_state_stays_two": all(
            case["budget_before"]["current_delegation_depth"] == 2
            for case in cases.values()
        ),
        "all_signatures_valid": all(case["signature_valid"] for case in cases.values()),
    }
    assert all(checks.values()), json.dumps({"upstream": upstream, "cases": cases}, indent=2)
    return {
        "repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "upstream_eval": upstream,
        "cases": cases,
        "checks": checks,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
