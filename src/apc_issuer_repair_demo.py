"""Illustrative bounded issuer for two APC reference-API defects.

This independent adapter is not an upstream patch or a production-ready
issuer.  It demonstrates that depth checking and unique branch IDs restore
the tested invariants while leaving the original PDP unchanged.
"""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
import time
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
from apc.pdp import (  # noqa: E402
    EvidenceSink, PolicyDecisionPoint, ProposedAction, RevocationRegistry,
)

KEY = b"bounded-issuer-demonstration-key"
SESSION = "bounded-issuer-session"


class BoundedIssuer:
    def __init__(self, key: bytes):
        self.key = key
        self.counter = itertools.count(1)

    def narrow(self, parent: AuthorizationEnvelope, delegate: Principal) -> AuthorizationEnvelope:
        if not parent.verify(self.key) or parent.is_expired:
            raise ValueError("invalid parent envelope")
        if parent.delegation_depth >= parent.budget_spec.max_delegation_depth:
            raise ValueError("delegation depth ceiling exceeded")
        child = AuthorizationEnvelope(
            envelope_id=f"{parent.envelope_id}/{next(self.counter)}",
            task_session_id=parent.task_session_id,
            originating_principal=parent.originating_principal,
            effective_scope=parent.effective_scope.meet(delegate.role_scope),
            budget_spec=parent.budget_spec,
            chain=[*parent.chain, delegate],
            created_at=time.time(),
            expires_at=parent.expires_at,
            policy_version=parent.policy_version,
        )
        child.sign(self.key)
        return child


def admitted(pdp, envelope, spec):
    action = ProposedAction(
        action_type="read", target_resource="docs:demo", parameters={},
        actor_principal_id=envelope.chain[-1].principal_id,
        task_session_id=SESSION, policy_version=envelope.policy_version,
        sensitivity_class="public",
    )
    result = pdp.evaluate(
        action, envelope, BudgetState(spec=spec),
        CompositionChecker(restrictions=frozenset()),
    )
    return result.admitted


def run(width=3, depth=3):
    scope = Scope(frozenset({"docs:demo"}), frozenset({"read"}), frozenset({"public"}))
    spec = DelegationBudgetSpec(depth, 1.0, 5, "public", True, 100.0)
    owner = Principal("user:owner", ExecutionRole.AS_USER, scope)
    root = AuthorizationEnvelope(
        envelope_id="repair-root", task_session_id=SESSION,
        originating_principal=owner, effective_scope=scope, budget_spec=spec,
    )
    root.sign(KEY)
    issuer = BoundedIssuer(KEY)
    levels = [[root]]
    for level in range(1, depth + 1):
        next_level = []
        for parent_i, parent in enumerate(levels[-1]):
            for branch in range(width):
                delegate = Principal(
                    f"agent:l{level}-p{parent_i}-b{branch}",
                    ExecutionRole.ON_BEHALF_OF, scope,
                )
                next_level.append(issuer.narrow(parent, delegate))
        levels.append(next_level)
    registry = RevocationRegistry()
    pdp = PolicyDecisionPoint(
        signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0, approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(), revocation_registry=registry,
    )
    all_envs = [env for group in levels for env in group]
    before = [admitted(pdp, env, spec) for env in all_envs]
    target = levels[-1][0]
    registry.revoke(target.envelope_id)
    after = [admitted(pdp, env, spec) for env in all_envs]
    depth_rejected = False
    try:
        issuer.narrow(
            target,
            Principal("agent:over-depth", ExecutionRole.ON_BEHALF_OF, scope),
        )
    except ValueError as error:
        depth_rejected = "depth" in str(error)
    output = {
        "repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "width": width,
        "depth_cap": depth,
        "envelopes": len(all_envs),
        "unique_ids": len({env.envelope_id for env in all_envs}),
        "all_signatures_valid": all(env.verify(KEY) for env in all_envs),
        "all_baseline_admitted": all(before),
        "denied_after_one_leaf_revoked": sum(not value for value in after),
        "depth_overflow_rejected_at_issuance": depth_rejected,
    }
    assert output["unique_ids"] == output["envelopes"]
    assert output["all_signatures_valid"] and output["all_baseline_admitted"]
    assert output["denied_after_one_leaf_revoked"] == 1
    assert output["depth_overflow_rejected_at_issuance"]
    return output


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
