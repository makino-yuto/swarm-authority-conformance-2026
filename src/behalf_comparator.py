"""Pinned independent Behalf revocation control; no models or real tools.

The dependency-free Python port is imported directly from its unchanged clone.
Run with python -B -S src/behalf_comparator.py to exclude optional site packages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
PIN = "556f91cc7f356a74d625d798321ad998288f1ab0"
REMOTE = "https://github.com/novaai0401-ui/agent-authority.git"


def git(repo: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()


def fixture(repo: Path) -> dict:
    sys.path.insert(0, str(repo / "python"))
    from agent_authority import create_behalf
    from agent_authority.errors import AuthorizationError

    # An injected, fixed clock makes all grants/proofs fresh deterministically.
    engine = create_behalf(now=lambda: 1_000_000, require_nonce=True)
    root = engine.grant(principal="synthetic-user", agent="root-agent",
                        can=["read:calendar"], expires_in="1h")
    # Identical agent label and scope deliberately test distinct grant identity.
    a = root.attenuate(can=["read:calendar"], agent="same-worker-label")
    b = root.attenuate(can=["read:calendar"], agent="same-worker-label")
    aa = a.attenuate(can=["read:calendar"], agent="grandchild-a")
    bb = b.attenuate(can=["read:calendar"], agent="grandchild-b")
    independent = engine.grant(principal="synthetic-user", agent="independent-root",
                               can=["read:calendar"], expires_in="1h")
    nodes = {"root": root, "a": a, "b": b, "aa": aa, "bb": bb,
             "independent_root": independent}
    identifiers = {name: mandate.id for name, mandate in nodes.items()}
    assert len(set(identifiers.values())) == len(nodes), "Separately issued grants collided"
    assert a.chain == [root.id, a.id] and b.chain == [root.id, b.id]
    assert aa.chain == [root.id, a.id, aa.id]
    assert bb.chain == [root.id, b.id, bb.id]
    observations = []

    def check(phase: str, name: str, expected_allowed: bool) -> None:
        try:
            nodes[name].authorize("read:calendar")
            allowed, reason = True, "authorized"
        except AuthorizationError as error:
            allowed, reason = False, str(error)
        assert allowed == expected_allowed, (phase, name, expected_allowed, allowed, reason)
        if not expected_allowed:
            assert "revoked" in reason.lower(), "Denied for an unrelated reason"
        observations.append({"phase": phase, "node": name,
                             "expected_allowed": expected_allowed,
                             "observed_allowed": allowed, "reason": reason})

    for name in nodes:
        check("before_revocation", name, True)
    a.revoke()
    for name in nodes:
        check("after_child_a_revocation", name, name not in ("a", "aa"))
    root.revoke()
    for name in nodes:
        check("after_root_revocation", name, name == "independent_root")

    return {"passed": True, "authorization_observations": len(observations),
            "checks": {"distinct_sibling_ids_with_identical_labels_and_scope": True,
                       "unrevoked_positive_controls": True,
                       "child_revocation_denies_its_descendant": True,
                       "child_revocation_preserves_sibling_and_sibling_descendant": True,
                       "child_revocation_preserves_root": True,
                       "root_revocation_denies_all_descendants": True,
                       "root_revocation_preserves_an_independent_root": True,
                       "every_expected_denial_is_revocation_specific": True},
            "ids": identifiers, "observations": observations}


def topology_fixture(repo: Path) -> dict:
    """Same 3-ary, depth-3, 40-grant shape as the APC branching audit.

    Depth describes the generated topology, not a Behalf maximum-depth policy.
    All grants have the same scope and every child has the same agent label.
    """
    sys.path.insert(0, str(repo / "python"))
    from agent_authority import create_behalf
    from agent_authority.errors import AuthorizationError

    engine = create_behalf(now=lambda: 1_000_000, require_nonce=True)
    root = engine.grant(principal="synthetic-user", agent="root-agent",
                        can=["read:calendar"], expires_in="1h")
    grants = {"root": root}
    depths = {"root": 0}
    frontier = ["root"]
    for depth in range(1, 4):
        following = []
        for parent_path in frontier:
            for branch in range(3):
                path = str(branch) if parent_path == "root" else f"{parent_path}.{branch}"
                grants[path] = grants[parent_path].attenuate(
                    can=["read:calendar"], agent="same-worker-label"
                )
                depths[path] = depth
                following.append(path)
        frontier = following
    independent = engine.grant(principal="synthetic-user", agent="independent-root",
                               can=["read:calendar"], expires_in="1h")
    identifiers = {path: grant.id for path, grant in grants.items()}
    assert len(grants) == 40 and len(frontier) == 27
    assert len(set(identifiers.values())) == 40
    assert independent.id not in set(identifiers.values())
    for path, grant in grants.items():
        assert len(grant.chain) == depths[path] + 1
    observations = []

    def check(phase: str, path: str, grant, expected_allowed: bool) -> bool:
        try:
            grant.authorize("read:calendar")
            allowed, reason = True, "authorized"
        except AuthorizationError as error:
            allowed, reason = False, str(error)
        assert allowed == expected_allowed, (phase, path, reason)
        if not expected_allowed:
            assert "revoked" in reason.lower(), "Denied for an unrelated reason"
        observations.append({"phase": phase, "node": path,
                             "expected_allowed": expected_allowed,
                             "observed_allowed": allowed, "reason": reason})
        return allowed

    baseline_allowed = sum(check("baseline", path, grant, True) for path, grant in grants.items())
    independent_before = check("baseline", "independent_root", independent, True)
    revoked_path = "0.0.0"
    assert depths[revoked_path] == 3
    grants[revoked_path].revoke()
    denied_paths = []
    after_allowed = 0
    for path, grant in grants.items():
        allowed = check("after_one_leaf_revocation", path, grant, path != revoked_path)
        after_allowed += int(allowed)
        if not allowed:
            denied_paths.append(path)
    independent_after = check("after_one_leaf_revocation", "independent_root", independent, True)
    assert baseline_allowed == 40 and after_allowed == 39 and denied_paths == [revoked_path]
    return {"passed": True, "branching_factor": 3, "tree_depth": 3,
            "tree_grants": 40, "tree_leaf_grants": 27,
            "unique_tree_grant_ids": len(set(identifiers.values())),
            "baseline_tree_allowed": baseline_allowed,
            "after_one_leaf_revocation_tree_allowed": after_allowed,
            "after_one_leaf_revocation_tree_denied": len(denied_paths),
            "revoked_leaf": revoked_path, "denied_tree_nodes": denied_paths,
            "collateral_tree_denials": len([path for path in denied_paths if path != revoked_path]),
            "independent_positive_control": {"baseline_allowed": independent_before,
                                              "after_revocation_allowed": independent_after},
            "authorization_observations": len(observations),
            "same_child_agent_label_and_scope": True,
            "topology_depth_is_not_a_tested_max_depth_policy": True,
            "ids": identifiers, "observations": observations}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=BASE / "alternatives" / "behalf_agent_authority")
    parser.add_argument("--output", type=Path, default=BASE / "results" / "apc" / "behalf_comparator.json")
    parser.add_argument("--reuse-full-suite-result", type=Path,
                        help="Reuse an earlier full-suite result at the identical pinned source, then run core tests and fixture")
    arguments = parser.parse_args()
    repo = arguments.repo.resolve()
    commit = git(repo, "rev-parse", "HEAD")
    assert commit == PIN, f"Expected {PIN}, found {commit}"
    assert git(repo, "remote", "get-url", "origin") == REMOTE
    before = git(repo, "status", "--porcelain", "--untracked-files=no")
    assert not before, "Comparator tracked source must be unchanged"
    source_files = ("python/agent_authority/behalf.py", "python/agent_authority/mandate.py",
                    "python/agent_authority/crypto.py", "python/agent_authority/_backend.py",
                    "python/tests/test_behalf.py", "python/pyproject.toml", "LICENSE")
    hashes = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in source_files}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(repo / "python"))
    command = [sys.executable, "-B", "-S", "-m", "unittest", "discover", "-s", "tests", "-v"]
    if arguments.reuse_full_suite_result:
        prior = json.loads(arguments.reuse_full_suite_result.read_text(encoding="utf-8"))
        assert prior["commit"] == commit and prior["source_sha256"] == hashes
        suite_summary = prior["official_tests"]
        suite_summary["reused_previous_identical_source_run"] = True
        print("Reusing the recorded full-suite run at identical pinned source.", flush=True)
    else:
        print("Running pinned official Behalf Python unittest suite without site packages...", flush=True)
        started = time.monotonic()
        suite = subprocess.run(command, cwd=repo / "python", env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
        elapsed = time.monotonic() - started
        combined = suite.stdout + "\n" + suite.stderr
        match = re.search(r"Ran (\d+) tests? in ([\d.]+)s", combined)
        suite_summary = {"command": command, "cwd": str(repo / "python"),
                         "return_code": suite.returncode, "elapsed_seconds": elapsed,
                         "tests_run": int(match.group(1)) if match else None,
                         "test_summary_tail": combined.strip().splitlines()[-6:],
                         "site_packages_disabled": True,
                         "new_dependencies_installed": False}
        if suite.returncode:
            suite_summary["failure_output_tail"] = combined.strip().splitlines()[-50:]
    result = {"repository": REMOTE.removesuffix(".git"), "commit": commit,
              "commit_date": git(repo, "show", "-s", "--format=%cI", "HEAD"),
              "license": "MIT", "python": sys.version,
              "source_sha256": hashes, "official_tests": suite_summary,
              "scope": "Independent local positive control for unique sibling grant IDs and branch-local/cascading revocation only. This does not test a maximum-depth property, cryptographic security, distributed revocation freshness, actual model behavior, or tool execution.",
              "caveats": ["Small independent project; no independent cryptographic audit claimed.",
                          "Optional native/sealed-credential tests may skip when site packages are disabled.",
                          "Authorization checks use one process and a shared in-memory revocation store.",
                          "The fixed-clock fixture checks declared API behavior, not wall-clock expiry."]}
    if suite_summary["return_code"]:
        result["caveats"].append(
            "The full official suite does NOT pass in this environment: 114 tests, one CLI quickstart/lint failure, six optional cryptography skips. Targeted core tests are reported separately and do not erase that failure."
        )
    core_names = ["test_behalf.RevocationTests.test_revoke_self",
                  "test_behalf.RevocationTests.test_revoke_root_cascades",
                  "test_behalf.RevocationTests.test_revoke_child_keeps_siblings"]
    core_command = [sys.executable, "-B", "-S", "-m", "unittest", "-v", *core_names]
    core_env = dict(env, PYTHONPATH=os.pathsep.join((str(repo / "python"), str(repo / "python" / "tests"))))
    print("Running three unchanged official core revocation tests...", flush=True)
    started = time.monotonic()
    core = subprocess.run(core_command, cwd=repo / "python", env=core_env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    core_output = core.stdout + "\n" + core.stderr
    core_match = re.search(r"Ran (\d+) tests? in ([\d.]+)s", core_output)
    result["official_core_tests"] = {"command": core_command, "test_names": core_names,
            "return_code": core.returncode, "elapsed_seconds": time.monotonic() - started,
            "tests_run": int(core_match.group(1)) if core_match else None,
            "output": core_output.strip(), "site_packages_disabled": True}
    if core.returncode:
        result["status"] = "targeted_core_tests_failed_fixture_not_run"
    else:
        print("Core tests passed; running independent sibling/cascade fixture...", flush=True)
        result["fixture"] = fixture(repo)
        print("Running matched 3-ary depth-3 40-grant branching fixture...", flush=True)
        result["topology_fixture"] = topology_fixture(repo)
        result["status"] = "core_and_fixture_passed_full_suite_has_cli_failure" if suite_summary["return_code"] else "passed"
    after = git(repo, "status", "--porcelain", "--untracked-files=no")
    assert not after, "Comparator tracked source changed while testing"
    result["tracked_source_unchanged"] = True
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "official_tests": {key: value for key, value in suite_summary.items() if key != "failure_output_tail"},
                      "official_core_tests": result["official_core_tests"],
                      "fixture_observations": result.get("fixture", {}).get("authorization_observations"),
                      "topology_summary": {key: value for key, value in result.get("topology_fixture", {}).items()
                                           if key not in ("ids", "observations")},
                      "output": str(arguments.output)}, indent=2))
    return 0 if result.get("fixture", {}).get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
