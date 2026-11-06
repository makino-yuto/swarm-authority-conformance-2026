"""Check revocation identity in APC's own DevOps case-study fixture.

This imports the unmodified Section 7 case study and runs low-impact,
legitimate actions through a fresh full PDP before and after one exact-ID
revocation. The fixture's signing key and principals are fictional.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "alternatives" / "bounded_agents"
PIN = "d31a1ea115a3e97ab972ac8d03f23ef36cf9b653"
sys.path.insert(0, str(REPO))

from apc.approval import ApprovalStore  # noqa: E402
from apc.budget import BudgetState  # noqa: E402
from apc.calibrate import ImpactWeights  # noqa: E402
from apc.compose import CompositionChecker  # noqa: E402
from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction, RevocationRegistry  # noqa: E402
from tests.test_case_studies import KEY, TestCaseStudyII  # noqa: E402


def run() -> dict:
    commit = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    if commit != PIN:
        raise RuntimeError(f"Unexpected APC commit: {commit}")
    case = TestCaseStudyII()
    case.setup_method()
    roles = {
        "planner": (case.plan_env, "plan", "infra:terraform", "agent:planner"),
        "reviewer": (case.review_env, "review", "infra:security-scan", "agent:security-reviewer"),
        "deployer": (case.deploy_env, "deploy", "infra:deploy", "agent:deployer"),
    }
    registry = RevocationRegistry()
    pdp = PolicyDecisionPoint(
        signing_key=KEY, impact_weights=ImpactWeights(0.5, 0.3, 0.2),
        approval_threshold=0.4, approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(), revocation_registry=registry,
    )

    def evaluate() -> dict:
        decisions = {}
        for label, (envelope, action_type, resource, actor) in roles.items():
            action = ProposedAction(
                action_type=action_type, target_resource=resource,
                parameters={}, actor_principal_id=actor,
                task_session_id="cs2-session", policy_version="1.0",
                sensitivity_class="internal",
            )
            decision = pdp.evaluate(
                action, envelope, BudgetState(spec=case.budget_spec),
                CompositionChecker(restrictions=frozenset()),
            )
            decisions[label] = {
                "admitted": decision.admitted,
                "denial_reasons": decision.denial_reasons,
                "identity_binding_passed": (
                    decision.condition_results["identity_binding"].passed
                    if "identity_binding" in decision.condition_results else None
                ),
            }
        return decisions

    ids = {label: item[0].envelope_id for label, item in roles.items()}
    signatures = {label: item[0].verify(KEY) for label, item in roles.items()}
    baseline = evaluate()
    registry.revoke(ids["planner"], "fictional planner grant revoked")
    after = evaluate()
    checks = {
        "three_roles_have_distinct_principals": len({x[3] for x in roles.values()}) == 3,
        "three_roles_share_one_id": len(set(ids.values())) == 1,
        "all_three_signatures_valid": all(signatures.values()),
        "all_three_legitimate_actions_admitted_before": all(x["admitted"] for x in baseline.values()),
        "all_three_denied_after_planner_id_revoked": all(not x["admitted"] for x in after.values()),
        "denials_are_revocation_specific": all(
            any("revok" in reason.lower() for reason in x["denial_reasons"])
            for x in after.values()
        ),
    }
    result = {
        "upstream_repository": "https://github.com/xmuruaga/bounded-agents",
        "commit": commit,
        "upstream_fixture": "tests/test_case_studies.py:TestCaseStudyII.setup_method",
        "grant_ids": ids,
        "signatures_valid": signatures,
        "baseline": baseline,
        "after_one_planner_id_revocation": after,
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "scope": "Local fixture and low-impact test actions only; no deployed DevOps system or real agent behavior.",
    }
    assert result["all_checks_pass"], result
    return result


if __name__ == "__main__":
    result = run()
    destination = ROOT / "results" / "apc" / "case_study_check.json"
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"grant_ids": result["grant_ids"], "checks": result["checks"]}, indent=2))
    print(destination)
