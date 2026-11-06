"""Tiny mechanism-level conformance diagnostic for paired 2x2 experiments.

Rows toggle a possible confound and columns toggle the claimed mechanism.
Each cell is a Boolean blocked/admitted verdict from a real evaluation.
This is a diagnostic structure, not a statistical causal estimate.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Diagnostic:
    name: str
    claimed_mechanism: str
    confound: str
    blocked: tuple[tuple[bool, bool], tuple[bool, bool]]
    published_confound_present: bool
    isolated_effect: int
    published_comparison_effect: int
    confound_alone_effect: int
    interpretation: str


def diagnose(
    name: str,
    claimed_mechanism: str,
    confound: str,
    blocked: tuple[tuple[bool, bool], tuple[bool, bool]],
    published_confound_present: bool,
) -> Diagnostic:
    """Compare verdict differences, holding the other mechanism fixed."""
    if len(blocked) != 2 or any(len(row) != 2 for row in blocked):
        raise ValueError("Expected a complete two-by-two Boolean matrix")
    if any(type(x) is not bool for row in blocked for x in row):
        raise TypeError("Cells must be Boolean verdicts")
    isolated = int(blocked[0][1]) - int(blocked[0][0])
    published_row = int(published_confound_present)
    published = int(blocked[published_row][1]) - int(blocked[published_row][0])
    confound_alone = int(blocked[1][0]) - int(blocked[0][0])
    if isolated == 0 and confound_alone == 1:
        label = "claimed mechanism has no blocking effect in the isolated probe; confound blocks"
    elif isolated == 1 and published == 0 and confound_alone == 1:
        label = "mechanism blocks when isolated, but published comparison is masked by confound"
    elif isolated == 1 and published == 1:
        label = "published comparison isolates a blocking effect in this probe"
    else:
        label = "mixed pattern; inspect the complete verdict and reason records"
    return Diagnostic(
        name=name,
        claimed_mechanism=claimed_mechanism,
        confound=confound,
        blocked=blocked,
        published_confound_present=published_confound_present,
        isolated_effect=isolated,
        published_comparison_effect=published,
        confound_alone_effect=confound_alone,
        interpretation=label,
    )


def from_apc_audit(audit: dict) -> list[Diagnostic]:
    d = audit["depth_ablation"]["cases"]
    k = audit["k_tuple_ablation"]["cases"]
    depth = diagnose(
        name="APC depth overflow named variant",
        claimed_mechanism="actual envelope depth exceeds signed maximum",
        confound="irreversible-effects budget exhausted",
        blocked=(
            (not d["legal_depth_control"]["admitted"],
             not d["remove_irreversible_preload"]["admitted"]),
            (not d["legal_depth_with_irreversible_preload"]["admitted"],
             not d["published_confound"]["admitted"]),
        ),
        published_confound_present=True,
    )
    ktup = diagnose(
        name="APC k-tuple bypass named variant",
        claimed_mechanism="ordered k-tuple rule enabled",
        confound="pairwise read-to-external-send rule enabled",
        blocked=(
            (k["isolated_no_pair_no_k"]["blocked"],
             k["isolated_no_pair_with_k"]["blocked"]),
            (k["original_pairwise_only"]["blocked"],
             k["original_pairwise_plus_k"]["blocked"]),
        ),
        published_confound_present=True,
    )
    assert depth.blocked == ((False, False), (True, True))
    assert ktup.blocked == ((False, True), (True, True))
    return [depth, ktup]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit", type=Path,
        default=Path(__file__).resolve().parents[1] / "results" / "apc" / "audit.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parents[1] / "results" / "apc" / "diagnostics.json",
    )
    args = parser.parse_args()
    data = json.loads(args.audit.read_text(encoding="utf-8"))
    diagnostics = [asdict(x) for x in from_apc_audit(data)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(diagnostics, indent=2))


if __name__ == "__main__":
    main()
