"""Run every local APC reproduction against the pinned upstream commit.

Usage:
    python src/run_apc_audit.py
    python src/run_apc_audit.py --output results/apc/audit.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import apc_depth_ablation
import apc_issuer_repair_demo
import apc_k_tuple_ablation
import apc_persistence_poc
import apc_restriction_binding_poc
import apc_revocation_poc


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "alternatives" / "bounded_agents"
PINNED_COMMIT = "d31a1ea115a3e97ab972ac8d03f23ef36cf9b653"
SOURCE_FILES = (
    "apc/core.py", "apc/pdp.py", "apc/budget.py", "apc/compose.py",
    "apc/approval.py", "evals/adaptive/run_adaptive.py",
)


def run() -> dict:
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    if actual != PINNED_COMMIT:
        raise RuntimeError(f"Upstream commit changed: {actual} != {PINNED_COMMIT}")
    status = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=REPO, text=True
    ).strip()
    if status:
        raise RuntimeError("Upstream checkout has local changes; use a clean pinned clone")
    logging.getLogger("apc").setLevel(logging.ERROR)
    result = {
        "metadata": {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "upstream_repo": "https://github.com/xmuruaga/bounded-agents",
            "upstream_commit": PINNED_COMMIT,
            "source_sha256": {
                name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                for name in SOURCE_FILES
            },
            "network_calls": 0,
            "external_model_calls": 0,
        },
        "depth_ablation": apc_depth_ablation.run(),
        "k_tuple_ablation": apc_k_tuple_ablation.run(),
        "restriction_binding": apc_restriction_binding_poc.run(),
        "revocation": apc_revocation_poc.run(),
        "branching_tree": apc_revocation_poc.run_branching_tree(),
        "default_depth_tracker": apc_revocation_poc.run_depth_budget(),
        "persistence_fault": apc_persistence_poc.run(),
        "illustrative_issuer_repair": apc_issuer_repair_demo.run(),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "results" / "apc" / "audit.json"
    )
    args = parser.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "saved": str(args.output),
        "commit": result["metadata"]["upstream_commit"],
        "depth3_without_irreversible_confound_admitted": result["depth_ablation"]["cases"][
            "remove_irreversible_preload"
        ]["admitted"],
        "same_depth_off_target_revocations": result["branching_tree"]["per_level"][-1][
            "denied_after_one_leaf_revocation"
        ] - 1,
        "failed_save_total_admitted_cost": result["persistence_fault"]["failed_save"][
            "total_admitted_cost"
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
