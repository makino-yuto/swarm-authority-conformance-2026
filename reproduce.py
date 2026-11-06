"""One-command local reproduction. Python 3.11+ and Git only."""
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

ROOT = Path(__file__).resolve().parent


def local_environment():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    count = int(env.get("GIT_CONFIG_COUNT", "0"))
    env["GIT_CONFIG_KEY_" + str(count)] = "core.longpaths"
    env["GIT_CONFIG_VALUE_" + str(count)] = "true"
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


def scrub(value):
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        for spelling in (str(ROOT), str(ROOT).replace("\\", "/")):
            value = value.replace(spelling, "<workspace>")
        if re.fullmatch(r"[A-Za-z]:[\\/].*python(?:\.exe)?", value, flags=re.I):
            return "python"
        value = re.sub(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\r\n\"']*", "<local-path>", value)
        value = re.sub(r"(?<![\w:])/(?:Users|home)/[^\s\"']+", "<local-path>", value)
        return value
    return value


def command(args, cwd=ROOT):
    completed = subprocess.run(args, cwd=cwd, text=True, encoding="utf-8", errors="replace",
                               capture_output=True, timeout=300, env=local_environment())
    if completed.returncode:
        raise RuntimeError(scrub("Command failed: " + repr(args) + "\n" + completed.stdout + completed.stderr))
    return completed.stdout.strip()


def clone(upstream, cache, offline):
    target = ROOT / "alternatives" / upstream["name"]
    if not target.resolve().is_relative_to(ROOT):
        raise ValueError("Checkout path escaped the release directory")
    if not target.exists():
        if cache is not None:
            source = cache / upstream["name"]
            if not source.is_dir():
                raise RuntimeError("Missing cached upstream: " + upstream["name"])
            command(["git", "-c", "core.autocrlf=false", "clone", "--no-hardlinks", "--no-checkout", str(source), str(target)])
            command(["git", "remote", "set-url", "origin", upstream["url"]], target)
            command(["git", "config", "core.autocrlf", "false"], target)
            command(["git", "checkout", "--detach", upstream["commit"]], target)
        else:
            if offline:
                raise RuntimeError("Missing pinned checkout in offline mode: " + upstream["name"])
            target.mkdir(parents=True)
            command(["git", "init"], target)
            command(["git", "config", "core.autocrlf", "false"], target)
            command(["git", "remote", "add", "origin", upstream["url"]], target)
            command(["git", "fetch", "--depth", "1", "origin", upstream["commit"]], target)
            command(["git", "checkout", "--detach", upstream["commit"]], target)
    actual = command(["git", "rev-parse", "HEAD"], target)
    if actual != upstream["commit"]:
        raise RuntimeError("Wrong checkout commit: " + upstream["name"])
    if command(["git", "status", "--porcelain"], target):
        raise RuntimeError("Upstream checkout is not clean: " + upstream["name"])


def validate_results(manifest):
    folder = ROOT / "results" / "apc"
    read = lambda name: json.loads((folder / name).read_text(encoding="utf-8"))
    audit = read("audit.json")
    kit = read("mandatekit_comparator.json")
    tree = read("mandatekit_tree_comparator.json")
    behalf = read("behalf_comparator.json")
    checks = {
        "apc_depth_counterfactual_admitted": audit["depth_ablation"]["cases"]["remove_irreversible_preload"]["admitted"] is True,
        "apc_tree_40_grants_4_ids": audit["branching_tree"]["total_envelopes"] == 40 and audit["branching_tree"]["unique_ids_total"] == 4,
        "apc_one_leaf_revocation_denies_27_leaves": audit["branching_tree"]["per_level"][-1]["denied_after_one_leaf_revocation"] == 27,
        "apc_failed_persistence_overspends_1_0_cap": audit["persistence_fault"]["failed_save"]["total_admitted_cost"] == 1.2,
        "mandatekit_depth_controls": kit["all_checks_pass"] is True,
        "mandatekit_tree_controls": tree["all_checks_pass"] is True and tree["unique_ids_total"] == 40 and tree["per_level"][-1]["denied_after_one_leaf_revocation"] == 1,
        "behalf_official_core_3_pass": behalf["official_core_tests"]["return_code"] == 0 and behalf["official_core_tests"]["tests_run"] == 3,
        "behalf_tree_controls": behalf["topology_fixture"]["passed"] is True and behalf["topology_fixture"]["unique_tree_grant_ids"] == 40 and behalf["topology_fixture"]["after_one_leaf_revocation_tree_denied"] == 1,
        "behalf_independent_positive_control": behalf["topology_fixture"]["independent_positive_control"]["after_revocation_allowed"] is True,
    }
    if manifest.get("graph_campaign_included"):
        graph = read("graph_contract_campaign.json")
        checks.update({
            "graph_90_records_45_native": len(graph["rows"]) == 90 and sum(x["cases"] for x in graph["native_summary"].values()) == 45,
            "graph_apc_target_pass_population_fail": graph["native_summary"]["apc"]["failing_cases_by_layer"] == {"target_verdict": 0, "target_condition": 0, "population_contract": 15},
            "graph_independent_native_controls_pass": all(all(v == 0 for v in graph["native_summary"][name]["failing_cases_by_layer"].values()) for name in ("mandatekit", "behalf")),
            "graph_offline_sources_unchanged": graph["metadata"]["source_before_after_identical"] and graph["metadata"]["blocked_network_attempts"] == 0,
        })
    if manifest.get("case_study_included"):
        case = read("case_study_check.json")
        checks["apc_upstream_case_study_revocation_reproduced"] = case["all_checks_pass"] is True and len(set(case["grant_ids"].values())) == 1
    if manifest.get("patch_validation_included"):
        repair = read("patch_validation.json")
        checks["illustrative_patch_fixture_checks"] = repair["all_checks_pass"] is True and repair["checks"]["baseline_checkout_unchanged"] is True
        checks["illustrative_patch_unique_ids_selective_revoke"] = repair["patched"]["tree"]["unique_ids"] == 40 and repair["patched"]["tree"]["denied_after_one_leaf_revoked"] == 1
    if not all(checks.values()):
        raise AssertionError(checks)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-cache", type=Path, help="Optional local cache containing the three named Git checkouts; no network then")
    parser.add_argument("--offline", action="store_true", help="Refuse network fetching; requires existing checkouts or --upstream-cache")
    options = parser.parse_args()
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    for relative, expected in manifest["files_sha256"].items():
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError("Package file changed: " + relative)
    for upstream in manifest["upstreams"]:
        print("Preparing pinned upstream " + upstream["name"], flush=True)
        clone(upstream, options.upstream_cache, options.offline)
    env = local_environment()
    scripts = ["run_apc_audit.py", "mechanism_conformance.py", "mandatekit_comparator.py",
               "mandatekit_tree_comparator.py", "behalf_comparator.py"]
    if manifest.get("graph_campaign_included"):
        scripts.append("graph_contract_campaign.py")
    if manifest.get("case_study_included"):
        scripts.append("apc_case_study_check.py")
    if manifest.get("patch_validation_included"):
        scripts.append("apc_patch_validation.py")
    logs = []
    for script in scripts:
        print("Running " + script, flush=True)
        started = time.monotonic()
        invocation = [sys.executable, "-B", "-S", str(ROOT / "src" / script)]
        if script == "apc_patch_validation.py":
            invocation.append("--skip-upstream-tests")
        completed = subprocess.run(invocation,
                                   cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
                                   capture_output=True, timeout=900 if script == "graph_contract_campaign.py" else 300)
        logs.append({"script": script, "return_code": completed.returncode,
                     "elapsed_seconds": round(time.monotonic() - started, 4),
                     "stdout": scrub(completed.stdout), "stderr": scrub(completed.stderr)})
        if completed.returncode:
            raise RuntimeError("Reproduction failed at " + script + "\n" + logs[-1]["stdout"] + logs[-1]["stderr"])
    checks = validate_results(manifest)
    for path in (ROOT / "results" / "apc").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(scrub(data), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {"passed": True, "checks": checks, "logs": logs,
               "model_calls": 0, "live_tool_actions": 0,
               "external_network_needed_during_experiments": False,
               "behalf_official_tests_use_loopback_http": True,
               "note": "Git fetching, if needed, occurs only in preparation; local fixtures do not exercise production tools. Behalf's official suite includes loopback HTTP test servers, and its full-suite CLI outcome is retained separately from passing core controls."}
    (ROOT / "results" / "reproduction_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "checks": checks, "results": "results/apc", "summary": "results/reproduction_summary.json"}, indent=2))


if __name__ == "__main__":
    main()
