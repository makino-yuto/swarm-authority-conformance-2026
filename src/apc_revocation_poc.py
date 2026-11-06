"""Reproduce revocation behavior in bounded-agents APC at a pinned commit.

Run from the bounded-agents repository root with:
    python ../..//src/apc_revocation_poc.py

This imports the unmodified reference implementation.  It performs only
in-memory authorization checks on fictitious principals and resources.
"""

from __future__ import annotations

import hashlib
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
    AuthorizationEnvelope,
    DelegationBudgetSpec,
    ExecutionRole,
    Principal,
    Scope,
)
from apc.pdp import (  # noqa: E402
    EvidenceSink,
    PolicyDecisionPoint,
    ProposedAction,
    RevocationRegistry,
)


KEY = b"apc-revocation-reproduction-key"
SESSION = "fictional-session"


def make_principal(name: str, role: ExecutionRole, scope: Scope) -> Principal:
    return Principal(name, role, scope)


def decision(
    pdp: PolicyDecisionPoint,
    envelope: AuthorizationEnvelope,
    spec: DelegationBudgetSpec,
    budget: BudgetState | None = None,
    checker: CompositionChecker | None = None,
) -> dict:
    budget = budget if budget is not None else BudgetState(spec=spec)
    checker = checker if checker is not None else CompositionChecker(restrictions=frozenset())
    action = ProposedAction(
        action_type="read",
        target_resource="docs:public-demo",
        parameters={},
        actor_principal_id=envelope.chain[-1].principal_id,
        task_session_id=SESSION,
        policy_version=envelope.policy_version,
        sensitivity_class="public",
    )
    result = pdp.evaluate(
        action,
        envelope,
        budget,
        checker,
    )
    return {
        "admitted": result.admitted,
        "denial_reasons": result.denial_reasons,
        "identity_binding": result.condition_results.get("identity_binding").passed
        if "identity_binding" in result.condition_results else None,
        "recorded_delegation_depth_after_action": budget.current_delegation_depth,
    }


def run() -> dict:
    scope = Scope(
        resources=frozenset({"docs:public-demo"}),
        actions=frozenset({"read"}),
        data_classifications=frozenset({"public"}),
    )
    spec = DelegationBudgetSpec(3, 1.0, 5, "confidential", True, 100.0)
    user = make_principal("user:owner", ExecutionRole.AS_USER, scope)
    agent_a = make_principal("agent:a", ExecutionRole.ON_BEHALF_OF, scope)
    agent_b = make_principal("agent:b", ExecutionRole.ON_BEHALF_OF, scope)
    worker_a = make_principal("agent:a-worker", ExecutionRole.ON_BEHALF_OF, scope)

    root = AuthorizationEnvelope(
        envelope_id="env-root",
        task_session_id=SESSION,
        originating_principal=user,
        effective_scope=scope,
        budget_spec=spec,
    )
    root.sign(KEY)
    a = root.narrow(agent_a, KEY)
    b = root.narrow(agent_b, KEY)
    a_child = a.narrow(worker_a, KEY)
    registry = RevocationRegistry()
    pdp = PolicyDecisionPoint(
        signing_key=KEY,
        impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
        revocation_registry=registry,
    )
    envs = {"root": root, "a": a, "b": b, "a_child": a_child}
    before = {name: decision(pdp, env, spec) for name, env in envs.items()}
    registry.revoke(a.envelope_id, "compromise of agent a")
    after = {name: decision(pdp, env, spec) for name, env in envs.items()}

    root_registry = RevocationRegistry()
    root_pdp = PolicyDecisionPoint(
        signing_key=KEY,
        impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
        revocation_registry=root_registry,
    )
    root_registry.revoke(root.envelope_id, "root compromised")
    after_root_revoke = {
        name: decision(root_pdp, env, spec) for name, env in envs.items()
    }

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    digests = {
        name: hashlib.sha256((REPO / "apc" / name).read_bytes()).hexdigest()
        for name in ("core.py", "pdp.py")
    }
    outcome = {
        "repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": commit,
        "source_sha256": digests,
        "envelopes": {
            name: {
                "id": env.envelope_id,
                "principal_chain": [p.principal_id for p in env.chain],
                "signature_valid": env.verify(KEY),
            }
            for name, env in envs.items()
        },
        "before_revocation": before,
        "after_revoking_a_id": after,
        "after_revoking_root_id_fresh_registry": after_root_revoke,
        "invariants": {
            "distinct_siblings_share_id": a.envelope_id == b.envelope_id
            and a.chain[-1].principal_id != b.chain[-1].principal_id,
            "all_baselines_admitted": all(v["admitted"] for v in before.values()),
            "revoked_a_denied": not after["a"]["admitted"],
            "unrelated_b_denied": not after["b"]["admitted"],
            "a_descendant_still_admitted": after["a_child"]["admitted"],
            "revoked_root_denied": not after_root_revoke["root"]["admitted"],
            "root_descendants_still_admitted": all(
                after_root_revoke[name]["admitted"] for name in ("a", "b", "a_child")
            ),
        },
    }
    assert all(outcome["invariants"].values()), json.dumps(outcome, indent=2)
    return outcome


def run_depth_budget() -> dict:
    """Exercise the signed delegation chain across the configured depth cap."""
    scope = Scope(
        resources=frozenset({"docs:public-demo"}),
        actions=frozenset({"read"}),
        data_classifications=frozenset({"public"}),
    )
    spec = DelegationBudgetSpec(2, 1.0, 5, "public", True, 100.0)
    owner = Principal("user:owner", ExecutionRole.AS_USER, scope)
    root = AuthorizationEnvelope(
        envelope_id="depth-root",
        task_session_id=SESSION,
        originating_principal=owner,
        effective_scope=scope,
        budget_spec=spec,
    )
    root.sign(KEY)
    envelopes = [root]
    for hop in range(1, 7):
        delegate = Principal(f"agent:hop-{hop}", ExecutionRole.ON_BEHALF_OF, scope)
        envelopes.append(envelopes[-1].narrow(delegate, KEY))

    pdp = PolicyDecisionPoint(
        signing_key=KEY,
        impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )
    shared_budget = BudgetState(spec=spec)
    shared_checker = CompositionChecker(restrictions=frozenset())
    results = [
        {
            "depth": env.delegation_depth,
            "depth_cap": env.budget_spec.max_delegation_depth,
            "signature_valid": env.verify(KEY),
            "decision": decision(pdp, env, spec, shared_budget, shared_checker),
        }
        for env in envelopes
    ]
    assert all(row["decision"]["admitted"] for row in results)
    assert any(row["depth"] > row["depth_cap"] for row in results)
    assert shared_budget.current_delegation_depth == 0
    return {"depth_budget_results": results}


def run_branching_tree(width: int = 3, depth: int = 3) -> dict:
    """Count off-target denials in a bounded, fully signed delegation tree."""
    scope = Scope(
        frozenset({"docs:public-demo"}), frozenset({"read"}), frozenset({"public"})
    )
    spec = DelegationBudgetSpec(depth, 1.0, 5, "public", True, 100.0)
    owner = Principal("user:tree-owner", ExecutionRole.AS_USER, scope)
    root = AuthorizationEnvelope(
        envelope_id="tree-root", task_session_id=SESSION,
        originating_principal=owner, effective_scope=scope, budget_spec=spec,
    )
    root.sign(KEY)
    levels = [[root]]
    for level in range(1, depth + 1):
        next_level = []
        for parent_index, parent in enumerate(levels[-1]):
            for branch in range(width):
                agent = Principal(
                    f"agent:l{level}-p{parent_index}-b{branch}",
                    ExecutionRole.ON_BEHALF_OF, scope,
                )
                next_level.append(parent.narrow(agent, KEY))
        levels.append(next_level)
    registry = RevocationRegistry()
    pdp = PolicyDecisionPoint(
        signing_key=KEY, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
        approval_threshold=1.0, approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(), revocation_registry=registry,
    )
    baseline = [decision(pdp, env, spec)["admitted"] for group in levels for env in group]
    target = levels[-1][0]
    registry.revoke(target.envelope_id, "one leaf compromised")
    after = [
        [decision(pdp, env, spec)["admitted"] for env in group]
        for group in levels
    ]
    outcome = {
        "width": width,
        "depth": depth,
        "total_envelopes": sum(map(len, levels)),
        "unique_ids_total": len({env.envelope_id for group in levels for env in group}),
        "per_level": [
            {
                "level": i,
                "envelopes": len(group),
                "unique_ids": len({env.envelope_id for env in group}),
                "denied_after_one_leaf_revocation": sum(not x for x in after[i]),
            }
            for i, group in enumerate(levels)
        ],
        "all_signatures_valid": all(env.verify(KEY) for group in levels for env in group),
        "all_baseline_admitted": all(baseline),
        "all_same_level_revoked": all(not x for x in after[-1]),
        "all_other_levels_admitted": all(all(group) for group in after[:-1]),
    }
    assert outcome["unique_ids_total"] == depth + 1
    assert all(outcome[name] for name in (
        "all_signatures_valid", "all_baseline_admitted",
        "all_same_level_revoked", "all_other_levels_admitted",
    ))
    return outcome


if __name__ == "__main__":
    print(json.dumps({
        "revocation": run(),
        "depth": run_depth_budget(),
        "branching_tree": run_branching_tree(),
    }, indent=2, sort_keys=True))
