"""Validate an illustrative APC depth/ID patch in an independent local clone.

    python -B src/apc_patch_validation.py --skip-upstream-tests

The default also runs the three relevant original pytest modules. Install
pytest==8.4.2 separately, or into the disposable clone's .audit-deps directory.
No models, credentials, live systems or transactions are used. The original
pinned checkout is read only. This is a bounded regression, not a security proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PINNED = "d31a1ea115a3e97ab972ac8d03f23ef36cf9b653"
BASELINE = ROOT / "alternatives" / "bounded_agents"
PATCH = ROOT / "patches" / "apc_depth_identity_fix.patch"
PATCHED = ROOT / "alternatives" / "bounded_agents_patch_validation"
MODULES = ["tests/test_core.py", "tests/test_budget.py", "tests/test_pdp.py"]


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=repo)


def fixture(repo: Path) -> dict:
    """Run in a fresh process so baseline and patched classes cannot mix."""
    sys.path.insert(0, str(repo))
    from apc.approval import ApprovalStore
    from apc.budget import ActionCost, BudgetState
    from apc.calibrate import ImpactWeights
    from apc.compose import CompositionChecker
    from apc.core import AuthorizationEnvelope, DelegationBudgetSpec, ExecutionRole, Principal, Scope
    from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction, RevocationRegistry

    key = b"fictional-patch-validation-key"
    scope = Scope(frozenset({"docs:fixture"}), frozenset({"read"}), frozenset({"public"}))
    owner = Principal("user:fixture", ExecutionRole.AS_USER, scope)
    worker = Principal("agent:same-label", ExecutionRole.ON_BEHALF_OF, scope)

    def spec(cap):
        return DelegationBudgetSpec(cap, 1.0, 5, "public", True, 100.0)

    def root(cap):
        env = AuthorizationEnvelope("fixture-root", "fixture-session", owner, scope, spec(cap))
        env.sign(key)
        return env

    def pdp(registry=None):
        return PolicyDecisionPoint(
            signing_key=key, impact_weights=ImpactWeights(0.4, 0.3, 0.3),
            approval_threshold=1.0, approval_store=ApprovalStore(),
            evidence_sink=EvidenceSink(), revocation_registry=registry,
        )

    def decide(env, tracker_depth=0, monitor=None):
        state = BudgetState(spec=spec(9))  # Deliberately looser runtime depth cap.
        assert state.consume(ActionCost(delegation_hops=tracker_depth)).allowed
        action = ProposedAction(
            action_type="read", target_resource="docs:fixture", parameters={},
            actor_principal_id=env.chain[-1].principal_id,
            task_session_id="fixture-session", policy_version=env.policy_version,
            sensitivity_class="public",
        )
        decision = (monitor or pdp()).evaluate(action, env, state, CompositionChecker())
        budget_result = decision.condition_results.get("budget")
        identity_result = decision.condition_results.get("identity_binding")
        return {"admitted": decision.admitted, "denial_reasons": decision.denial_reasons,
                "signature_valid": env.verify(key),
                "budget_condition": budget_result.passed if budget_result else None,
                "identity_condition": identity_result.passed if identity_result else None,
                "tracker_depth": state.current_delegation_depth}

    issuance = []
    for cap in [0, 2]:
        env = root(cap)
        for _ in range(cap):
            env = env.narrow(worker, key)
        try:
            child = env.narrow(worker, key)
            row = {"cap": cap, "child_issued": True, "child_depth": child.delegation_depth,
                   "signature_valid": child.verify(key)}
        except ValueError as error:
            row = {"cap": cap, "child_issued": False, "error": str(error)}
        issuance.append(row)

    # A trusted signer can construct a valid over-depth grant without narrow().
    # This models a preexisting grant / separate issuer and tests PDP defense.
    admission = []
    for actual_depth in [2, 3]:
        env = AuthorizationEnvelope(
            f"direct-depth-{actual_depth}", "fixture-session", owner, scope, spec(2),
            chain=[owner] + [worker] * actual_depth,
        )
        env.sign(key)
        for tracker in [0, 2]:
            admission.append({"signed_cap": 2, "actual_depth": actual_depth,
                              "initial_tracker_depth": tracker, **decide(env, tracker)})

    levels = [[root(3)]]
    for _ in range(3):
        levels.append([parent.narrow(worker, key) for parent in levels[-1] for _ in range(3)])
    nodes = [env for level in levels for env in level]
    registry = RevocationRegistry()
    monitor = pdp(registry)
    before = [decide(env, monitor=monitor) for env in nodes]
    target = nodes[-1]
    registry.revoke(target.envelope_id, "fictional target leaf")
    after = [decide(env, monitor=monitor) for env in nodes]
    denied = [index for index, row in enumerate(after) if not row["admitted"]]
    tree = {"width": 3, "depth": 3, "grants": len(nodes),
            "unique_ids": len({env.envelope_id for env in nodes}),
            "all_signatures_valid": all(row["signature_valid"] for row in before),
            "baseline_admitted": sum(row["admitted"] for row in before),
            "denied_after_one_leaf_revoked": len(denied),
            "target_leaf_denied": len(nodes) - 1 in denied,
            "off_target_denials": len([i for i in denied if i != len(nodes) - 1]),
            "same_child_principal_label_and_scope": True}
    return {"issuance": issuance, "admission": admission, "tree": tree}


def run_fixture(repo: Path) -> dict:
    command = [sys.executable, "-B", str(Path(__file__).resolve()),
               "--fixture-worker", "--patched-repo", str(repo)]
    run = subprocess.run(command, text=True, capture_output=True)
    if run.returncode:
        raise RuntimeError(f"Fixture failed for {repo}:\n{run.stdout}\n{run.stderr}")
    return json.loads(run.stdout)


def original_tests(repo: Path, pytest_path: Path, skip: bool) -> dict:
    if skip:
        return {"run": False, "reason": "Explicit --skip-upstream-tests", "modules": MODULES}
    env = os.environ.copy()
    paths = [str(repo)]
    if pytest_path.is_dir():
        paths.append(str(pytest_path))
    env["PYTHONPATH"] = os.pathsep.join(paths)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    command = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *MODULES]
    run = subprocess.run(command, cwd=repo, env=env, text=True, capture_output=True)
    output = (run.stdout + run.stderr).strip()
    count = re.search(r"(\d+) passed", output)
    return {"run": True, "command": command, "modules": MODULES,
            "returncode": run.returncode, "passed": int(count[1]) if count else None,
            "output": output, "plugin_autoload_disabled": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patched-repo", type=Path, default=PATCHED)
    parser.add_argument("--output", type=Path, default=ROOT / "results/apc/patch_validation.json")
    parser.add_argument("--pytest-path", type=Path)
    parser.add_argument("--skip-upstream-tests", action="store_true")
    parser.add_argument("--fixture-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo = args.patched_repo.resolve()
    if args.fixture_worker:
        print(json.dumps(fixture(repo)))
        return

    if repo == BASELINE.resolve():
        raise RuntimeError("Refusing to patch the baseline checkout")
    if git(BASELINE, "rev-parse", "HEAD").decode().strip() != PINNED:
        raise RuntimeError("Baseline commit differs from recorded pin")
    if git(BASELINE, "status", "--porcelain"):
        raise RuntimeError("Baseline checkout is not clean")
    baseline_hashes = {name: hashlib.sha256((BASELINE / name).read_bytes()).hexdigest()
                       for name in ["apc/core.py", "apc/pdp.py"]}
    subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=BASELINE, check=True)
    if not repo.exists():
        subprocess.run(["git", "clone", "--no-hardlinks", "--local", str(BASELINE), str(repo)], check=True)
    if git(repo, "rev-parse", "HEAD").decode().strip() != PINNED:
        raise RuntimeError("Disposable clone has the wrong commit")
    difference = git(repo, "diff", "--", "apc/core.py", "apc/pdp.py")
    if not difference:
        subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=repo, check=True)
        subprocess.run(["git", "apply", str(PATCH)], cwd=repo, check=True)
    if git(repo, "diff", "--", "apc/core.py", "apc/pdp.py") != PATCH.read_bytes():
        raise RuntimeError("Disposable clone's patch differs from the supplied patch")
    changed = git(repo, "diff", "--name-only").decode().splitlines()
    if sorted(changed) != ["apc/core.py", "apc/pdp.py"]:
        raise RuntimeError("Unexpected tracked edits in the disposable clone")

    baseline = run_fixture(BASELINE)
    patched = run_fixture(repo)
    tests = original_tests(repo, (args.pytest_path or repo / ".audit-deps").resolve(), args.skip_upstream_tests)
    checks = {
        "baseline_reproduces_depth_issuance": all(row["child_issued"] for row in baseline["issuance"]),
        "patched_refuses_over_depth_at_issuance": all(not row["child_issued"] for row in patched["issuance"]),
        "all_direct_grant_signatures_valid": all(row["signature_valid"] for row in patched["admission"]),
        "baseline_admits_all_direct_depth_probes": all(row["admitted"] for row in baseline["admission"]),
        "patched_admits_legal_depth_and_denies_over_depth": all(
            row["admitted"] == (row["actual_depth"] <= row["signed_cap"])
            for row in patched["admission"]),
        "patched_over_depth_denial_is_depth_budget": all(
            not row["budget_condition"] and row["identity_condition"]
            and any("delegation_depth" in reason for reason in row["denial_reasons"])
            for row in patched["admission"] if row["actual_depth"] == 3),
        "baseline_tree_reproduces_collision": baseline["tree"]["unique_ids"] == 4
            and baseline["tree"]["denied_after_one_leaf_revoked"] == 27,
        "patched_tree_unique_ids": patched["tree"]["unique_ids"] == 40,
        "both_trees_valid_and_baseline_available": all(
            x["tree"]["all_signatures_valid"] and x["tree"]["baseline_admitted"] == 40
            for x in [baseline, patched]),
        "patched_revokes_only_target_leaf": patched["tree"]["target_leaf_denied"]
            and patched["tree"]["denied_after_one_leaf_revoked"] == 1
            and patched["tree"]["off_target_denials"] == 0,
        "baseline_checkout_unchanged": not git(BASELINE, "status", "--porcelain")
            and all(hashlib.sha256((BASELINE / name).read_bytes()).hexdigest() == digest
                    for name, digest in baseline_hashes.items()),
        "patch_applies_cleanly_to_baseline": True,
    }
    if tests["run"]:
        checks["relevant_original_tests_pass"] = tests["returncode"] == 0
    result = {
        "repository": "https://github.com/xmuruaga/bounded-agents", "base_commit": PINNED,
        "python": platform.python_version(), "patched_clone": str(repo),
        "patch_file": str(PATCH), "patch_sha256": hashlib.sha256(PATCH.read_bytes()).hexdigest(),
        "changed_source_files": changed, "baseline_source_sha256": baseline_hashes,
        "patched_source_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                                   for name in baseline_hashes},
        "baseline": baseline, "patched": patched, "original_tests": tests,
        "checks": checks, "all_checks_pass": all(checks.values()),
        "semantics_and_limits": [
            "narrow() now raises ValueError before issuing a child beyond its parent's signed maximum depth.",
            "PDP admission independently compares the signed chain's depth with the signed cap, even with an unseeded or looser runtime tracker.",
            "UUIDv4 IDs replace depth-derived child IDs; this provides probabilistic per-grant uniqueness, not a distributed allocation guarantee.",
            "Root IDs remain caller supplied. Previously issued colliding envelopes are not migrated; those would require reissuance or a separate migration policy.",
            "The fixture uses repeated child labels and scope; grants remain independently identifiable and a selected leaf alone is revoked.",
            "Exact-ID revocation semantics are preserved. Ancestor-cascade revocation is neither added nor claimed.",
            "The shared test HMAC trust model, issuer authentication, other budget dimensions, persistence and composition wiring are unchanged.",
            "The original adaptive overflow case now raises at issuance; its legacy expected output must be updated if run against this patch.",
            "All checks are bounded local synthetic regressions. No cryptographic audit, live exploit, deployment guarantee or exhaustive proof is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"saved": str(args.output), "all_checks_pass": result["all_checks_pass"],
                      "original_tests_passed": tests.get("passed"), "checks": checks}, indent=2))
    if not result["all_checks_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
