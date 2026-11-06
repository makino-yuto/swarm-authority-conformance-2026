"""Show the effect of checker-policy wiring on a signed child restriction.

The reference API accepts a CompositionChecker independently of the signed
envelope.  This is a configuration consistency test, not an attacker model.
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

KEY = b"restriction-binding-reproduction-key"


def run_case(bind_child_restrictions: bool):
    resources = frozenset({"docs:demo", "email:external"})
    actions = frozenset({"read_confidential", "external_send"})
    classes = frozenset({"public", "confidential"})
    forbidden = frozenset({("read_confidential", "external_send")})
    root_scope = Scope(resources, actions, classes)
    child_role_scope = Scope(resources, actions, classes, forbidden)
    spec = DelegationBudgetSpec(2, 1.0, 5, "confidential", True, 100.0)
    owner = Principal("user:owner", ExecutionRole.AS_USER, root_scope)
    agent = Principal("agent:restricted-worker", ExecutionRole.ON_BEHALF_OF, child_role_scope)
    root = AuthorizationEnvelope(
        envelope_id="composition-root", task_session_id="composition-session",
        originating_principal=owner, effective_scope=root_scope, budget_spec=spec,
    )
    root.sign(KEY)
    child = root.narrow(agent, KEY)
    checker = CompositionChecker(
        restrictions=child.effective_scope.composition_restrictions
        if bind_child_restrictions else root.effective_scope.composition_restrictions
    )
    pdp = PolicyDecisionPoint(
        signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0, approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )
    budget = BudgetState(spec=spec)
    results = []
    for action_type, resource, sensitivity in (
        ("read_confidential", "docs:demo", "confidential"),
        ("external_send", "email:external", "public"),
    ):
        action = ProposedAction(
            action_type=action_type, target_resource=resource, parameters={},
            actor_principal_id=agent.principal_id,
            task_session_id="composition-session", policy_version="1.0",
            sensitivity_class=sensitivity,
        )
        decision = pdp.evaluate(action, child, budget, checker)
        results.append({
            "action": action_type,
            "admitted": decision.admitted,
            "denial_reasons": decision.denial_reasons,
            "conditions": {
                name: entry.passed for name, entry in decision.condition_results.items()
            },
        })
    return {
        "bind_child_restrictions": bind_child_restrictions,
        "child_signature_valid": child.verify(KEY),
        "signed_child_restriction": list(map(list, sorted(child.effective_scope.composition_restrictions))),
        "results": results,
    }


def run():
    root_checker = run_case(False)
    child_checker = run_case(True)
    checks = {
        "signed_restriction_present": root_checker["signed_child_restriction"] == [
            ["read_confidential", "external_send"]
        ],
        "all_signatures_valid": root_checker["child_signature_valid"]
        and child_checker["child_signature_valid"],
        "root_checker_read_admitted": root_checker["results"][0]["admitted"],
        "root_checker_send_admitted": root_checker["results"][1]["admitted"],
        "bound_checker_read_admitted": child_checker["results"][0]["admitted"],
        "bound_checker_send_denied": not child_checker["results"][1]["admitted"],
    }
    assert all(checks.values()), json.dumps({"root": root_checker, "child": child_checker}, indent=2)
    return {
        "repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "shared_root_checker": root_checker,
        "child_restriction_checker_control": child_checker,
        "checks": checks,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
