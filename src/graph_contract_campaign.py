"""Small Track 3 grant-population experiment, not a new testing method.

Calls pinned APC, MandateKit and Behalf Python APIs on matched graph shapes.
Credential copies are one grant; separately issued siblings are distinct grants.
Display aliases are an out-of-band model, NOT an SDK-native rename operation.
Three hand-selected Behalf infrastructure/issuance faults are sensitivity checks,
not discovered upstream vulnerabilities or a representative mutation sample.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import platform
import random
import socket
import subprocess
import sys
import time
from unittest.mock import patch

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
REPOS = {
    "apc": (BASE / "alternatives/bounded_agents", "d31a1ea115a3e97ab972ac8d03f23ef36cf9b653"),
    "mandatekit": (BASE / "alternatives/mandatekit", "fc6a3745ef3eab5ee1e8842f275a5666cf9ffc4f"),
    "behalf": (BASE / "alternatives/behalf_agent_authority", "556f91cc7f356a74d625d798321ad998288f1ab0"),
}
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)
LABEL_MODES = ("same_label", "distinct_labels", "alpha_renamed_same_label")
PROBE_LAYERS = ("target_verdict", "target_condition", "population_contract")


@dataclass(frozen=True)
class Node:
    index: int
    parent: int | None
    depth: int


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "--no-optional-locks", "-C", str(repo), *args], text=True
    ).strip()


def source_state() -> dict:
    result = {}
    for name, (repo, pin) in REPOS.items():
        commit = git(repo, "rev-parse", "HEAD")
        if commit != pin or git(repo, "status", "--porcelain", "--untracked-files=no"):
            raise RuntimeError(f"{name} must be an unchanged pinned checkout")
        tracked = git(repo, "ls-files").splitlines()
        # Only hash Python implementation files; do not execute source during this step.
        files = [p for p in tracked if p.endswith(".py") and
                 (p.startswith("apc/") or p.startswith("python/mandatekit/") or
                  p.startswith("python/agent_authority/"))]
        result[name] = {
            "commit": commit,
            "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in files},
        }
    return result


def balanced(width: int, depth: int) -> dict:
    nodes = [Node(0, None, 0)]
    frontier = [0]
    for level in range(1, depth + 1):
        following = []
        for parent in frontier:
            for _ in range(width):
                index = len(nodes)
                nodes.append(Node(index, parent, level))
                following.append(index)
        frontier = following
    return {"name": f"balanced_b{width}_d{depth}", "width": width,
            "max_depth": depth, "nodes": nodes, "balanced": True}


def irregular(seed: int = 41) -> dict:
    rng = random.Random(seed)
    nodes = [Node(0, None, 0)]
    for _ in range(2):
        parent = 0
        for level in range(1, 4):
            i = len(nodes)
            nodes.append(Node(i, parent, level))
            parent = i
    for _ in range(4):
        parent = rng.choice([n for n in nodes if n.depth < 3])
        nodes.append(Node(len(nodes), parent.index, parent.depth + 1))
    return {"name": f"irregular_seed{seed}", "seed": seed,
            "max_depth": 3, "nodes": nodes, "balanced": False}


def label(index: int, mode: str) -> str:
    if index == 0:
        return "root-owner"
    if mode == "same_label":
        return "worker"
    if mode == "alpha_renamed_same_label":
        return "display-name-changed-worker"
    return f"worker-{index}"


class APC:
    name = "apc"

    def __init__(self, graph: dict, mode: str, fault: str = "none"):
        from apc.approval import ApprovalStore
        from apc.budget import BudgetState
        from apc.calibrate import ImpactWeights
        from apc.compose import CompositionChecker
        from apc.core import AuthorizationEnvelope, DelegationBudgetSpec, ExecutionRole, Principal, Scope
        from apc.pdp import EvidenceSink, PolicyDecisionPoint, ProposedAction, RevocationRegistry
        assert fault == "none"
        self.BudgetState, self.Checker, self.Action = BudgetState, CompositionChecker, ProposedAction
        self.key = b"public-synthetic-graph-test-key"
        self.scope = Scope(frozenset({"docs:synthetic"}), frozenset({"read"}), frozenset({"public"}))
        self.spec = DelegationBudgetSpec(graph["max_depth"], 1.0, 5, "public", True, 100.0)
        owner = Principal("root-owner", ExecutionRole.AS_USER, self.scope)
        root = AuthorizationEnvelope("graph-root", "graph-session", owner, self.scope, self.spec,
                                     expires_at=4_000_000_000)
        root.sign(self.key)
        self.handles = [root]
        for node in graph["nodes"][1:]:
            principal = Principal(label(node.index, mode), ExecutionRole.ON_BEHALF_OF, self.scope)
            self.handles.append(self.handles[node.parent].narrow(principal, self.key))
        self.registry = RevocationRegistry()
        self.pdp = PolicyDecisionPoint(self.key, ImpactWeights(.4, .3, .3), 1.0,
                                       ApprovalStore(), EvidenceSink(), self.registry)

    def ident(self, h):
        return h.envelope_id

    def valid(self, h):
        return h.verify(self.key)

    def clone(self, h):
        return copy.deepcopy(h)

    def authorize(self, h):
        action = self.Action("read", "docs:synthetic", {}, h.chain[-1].principal_id,
                             h.task_session_id, h.policy_version)
        result = self.pdp.evaluate(action, h, self.BudgetState(spec=self.spec), self.Checker())
        reasons = result.denial_reasons
        category = "revocation" if any("revoked" in r for r in reasons) else ("allow" if result.admitted else "other")
        return {"allowed": result.admitted, "condition": category, "reasons": reasons}

    def revoke(self, h):
        self.registry.revoke(h.envelope_id)


class MandateKit:
    name = "mandatekit"

    def __init__(self, graph: dict, mode: str, fault: str = "none"):
        import mandatekit as mk
        from mandatekit.signing import _public_from_seed
        assert fault == "none"
        self.mk = mk
        self.issuer = hashlib.sha256(b"graph-root-issuer").digest()
        self.seeds = [hashlib.sha256(f"graph-node-{n.index}".encode()).digest() for n in graph["nodes"]]
        root = mk.sign_mandate(mk.build_mandate(
            agent_id=label(0, mode), agent_public_key=_public_from_seed(self.seeds[0]),
            categories=["synthetic"], merchants={"allow": ["local-synthetic"]},
            max_amount={"value": 0, "currency": "USD"}, actions=["read"],
            revocation={"list_id": "graph-list"}, delegation={"max_depth": graph["max_depth"]},
            issued_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(hours=1)), self.issuer)
        self.handles = [root]
        for node in graph["nodes"][1:]:
            child = mk.delegate_mandate(
                self.handles[node.parent], agent_id=label(node.index, mode),
                agent_public_key=_public_from_seed(self.seeds[node.index]),
                max_depth=graph["max_depth"] - node.depth,
                revocation={"list_id": "graph-list"}, issued_at=NOW - timedelta(hours=1))
            self.handles.append(mk.sign_mandate(child, self.seeds[node.parent]))
        self.root_public = root["signature"]["public_key"]
        self.revoked = []
        self.transaction = {"action": "read", "merchant": "local-synthetic", "category": "synthetic",
                            "amount": {"value": 0, "currency": "USD"}}

    def ident(self, h):
        return h["mandate"]["mandate_id"]

    def valid(self, h):
        return self.mk.verify_signature(h)

    def clone(self, h):
        return json.loads(json.dumps(h))

    def authorize(self, h):
        rev = self.mk.sign_revocation_list(self.mk.build_revocation_list(
            list_id="graph-list", revoked=self.revoked, issued_at=NOW), self.issuer)
        result = self.mk.verify(h, self.transaction, trusted_keys=[self.root_public],
                                now=NOW, revocation_lists=[rev])
        failed = result["failed"]
        allowed = result["decision"] == "allow"
        category = "revocation" if any(x["constraint"] == "revoked" for x in failed) else ("allow" if allowed else "other")
        return {"allowed": allowed, "condition": category, "reasons": failed}

    def revoke(self, h):
        self.revoked.append(self.ident(h))


class FaultRevocationStore:
    """Artificial infrastructure fault; it is NOT an upstream SDK defect."""
    def __init__(self, mode: str, labels: dict):
        self.mode, self.labels, self.revoked = mode, labels, set()

    def revoke(self, ident):
        self.revoked.add(ident)

    def is_revoked(self, ident):
        if self.mode == "ignore_revocation":
            return False
        if self.mode == "label_indexed_revocation":
            return ident in self.revoked or any(
                ident in self.labels and self.labels.get(ident) == self.labels.get(r)
                for r in self.revoked)
        return ident in self.revoked


class Behalf:
    name = "behalf"

    def __init__(self, graph: dict, mode: str, fault: str = "none"):
        from agent_authority import create_behalf
        from agent_authority.errors import AuthorizationError
        self.AuthorizationError = AuthorizationError
        self.labels = {}
        config = {"now": lambda: 1_000_000, "require_nonce": True}
        if fault in ("label_indexed_revocation", "ignore_revocation"):
            config["revocations"] = FaultRevocationStore(fault, self.labels)
        self.engine = create_behalf(**config)
        root = self.engine.grant(principal="synthetic-owner", agent=label(0, mode),
                                  can=["read:calendar"], expires_in="1h")
        self.handles = [root]
        bh_module = importlib.import_module("agent_authority.behalf")
        for node in graph["nodes"][1:]:
            if fault == "id_collision_at_depth":
                # Change only ID generation at issuance, BEFORE the real SDK signs.
                with patch.object(bh_module, "new_id", lambda: f"artificial-depth-id-{node.depth}"):
                    child = self.handles[node.parent].attenuate(can=["read:calendar"], agent=label(node.index, mode))
            else:
                child = self.handles[node.parent].attenuate(can=["read:calendar"], agent=label(node.index, mode))
            self.handles.append(child)
        self.labels.update({h.id: label(i, mode) for i, h in enumerate(self.handles)})

    def ident(self, h):
        return h.id

    def valid(self, h):
        self.engine.verify_signature(h.token)
        return True

    def clone(self, h):
        # An actual holder-credential export/import, using only synthetic keys.
        # Never serialize that holder credential into the result artifact.
        return self.engine.import_(h.serialize_with_key())

    def authorize(self, h):
        try:
            h.authorize("read:calendar")
            return {"allowed": True, "condition": "allow", "reasons": []}
        except self.AuthorizationError as error:
            reason = str(error)
            return {"allowed": False, "condition": "revocation" if "revoked" in reason.lower() else "other",
                    "reasons": [reason]}

    def revoke(self, h):
        h.revoke()


def run_population(adapter_class, graph: dict, label_mode: str, fault: str = "none") -> dict:
    adapter = adapter_class(graph, label_mode, fault)
    nodes = graph["nodes"]
    target_index = next(n.index for n in nodes if n.depth == graph["max_depth"])
    target = adapter.handles[target_index]
    ids = [adapter.ident(h) for h in adapter.handles]
    valid = all(adapter.valid(h) for h in adapter.handles)
    copied = adapter.clone(target)
    copy_same_id = adapter.ident(copied) == adapter.ident(target)
    copy_signature_valid = adapter.valid(copied)
    before = [adapter.authorize(h) for h in adapter.handles]
    copy_before = adapter.authorize(copied)
    # Presentation-only rename: no SDK has a tested mutable display-alias API.
    # This wrapper model does not change signed subjects or claim SDK rename support.
    presentation = {"alias": "before-display-name", "credential": target}
    rename_before_id = adapter.ident(presentation["credential"])
    presentation["alias"] = "after-display-name"
    rename_stable = adapter.ident(presentation["credential"]) == rename_before_id
    adapter.revoke(target)
    after = [adapter.authorize(h) for h in adapter.handles]
    copy_after = adapter.authorize(copied)
    target_denied = not after[target_index]["allowed"]
    target_condition = after[target_index]["condition"] == "revocation"
    all_before = all(v["allowed"] for v in before)
    off_target = [n.index for n, v in zip(nodes, after) if n.index != target_index and not v["allowed"]]
    target_verdict_ok = all_before and target_denied
    target_condition_ok = target_verdict_ok and target_condition
    exact_ok = (target_condition_ok and len(set(ids)) == len(ids) and not off_target and
                copy_same_id and copy_signature_valid and copy_before["allowed"] and
                not copy_after["allowed"] and rename_stable)
    target_collision_indices = [i for i, ident in enumerate(ids) if ident == ids[target_index]]
    groups = {}
    id_groups = [groups.setdefault(ident, len(groups)) for ident in ids]
    row = {
        "framework": adapter.name, "fault": fault, "topology": graph["name"],
        "label_mode": label_mode, "independently_issued_grants": len(nodes),
        "unique_grant_ids": len(set(ids)), "target_node": target_index,
        "target_collision_class_size": len(target_collision_indices),
        "target_collision_node_indices": target_collision_indices,
        "all_signatures_valid": valid, "all_before_allowed": all_before,
        "target_denied": target_denied, "target_denial_condition": after[target_index]["condition"],
        "total_denials_after_leaf_revocation": sum(not v["allowed"] for v in after),
        "off_target_denials": len(off_target), "off_target_node_indices": off_target,
        "credential_copy": {"api": "holder serialize/import" if adapter.name == "behalf" else "lossless credential object copy",
                            "same_grant_id": copy_same_id, "signature_valid": copy_signature_valid,
                            "before_allowed": copy_before["allowed"], "after_allowed": copy_after["allowed"],
                            "counted_as_independent_grant": False},
        "display_rename": {"layer": "out-of-band presentation wrapper ONLY; not SDK-native rename",
                           "id_stable": rename_stable, "signed_subject_modified": False},
        "probe_pass": dict(zip(PROBE_LAYERS, (target_verdict_ok, target_condition_ok, exact_ok))),
        "authorization_queries": 2 * len(nodes) + 2,
        "nodes": [{"index": n.index, "parent": n.parent, "depth": n.depth,
                   "id_equivalence_group": id_groups[n.index],
                   "before_allowed": before[n.index]["allowed"],
                   "after_allowed": after[n.index]["allowed"],
                   "after_condition": after[n.index]["condition"]} for n in nodes],
    }
    if not valid or not copy_signature_valid:
        raise AssertionError("A mutation invalidated cryptography rather than the selected contract")
    if adapter.name == "apc":
        expected = len(target_collision_indices) - 1
        row["apc_formula_check"] = {
            "unique_ids_equal_max_depth_plus_one": len(set(ids)) == graph["max_depth"] + 1,
            "off_target_equal_target_depth_population_minus_one": len(off_target) == expected,
            "predicted_off_target": expected,
        }
        if graph.get("balanced"):
            row["apc_formula_check"]["balanced_b_to_d_minus_one"] = graph["width"] ** graph["max_depth"] - 1
            row["apc_formula_check"]["balanced_formula_matches_measured_off_target"] = (
                len(off_target) == graph["width"] ** graph["max_depth"] - 1)
        assert all(v for k, v in row["apc_formula_check"].items() if isinstance(v, bool))
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=BASE / "results/apc/graph_contract_campaign.json")
    args = parser.parse_args()
    before_sources = source_state()
    for repo, _ in REPOS.values():
        sys.path.insert(0, str(repo / "python") if (repo / "python").exists() else str(repo))
    graphs = [balanced(2, 1), balanced(2, 2), balanced(3, 2), balanced(2, 3), irregular()]
    rows = []
    started = time.perf_counter()
    blocked_network_attempts = []

    def deny_network(*args, **kwargs):
        blocked_network_attempts.append("socket connection attempted")
        raise RuntimeError("This campaign is offline")

    with patch.object(socket.socket, "connect", deny_network), patch.object(socket, "create_connection", deny_network):
        for adapter in (APC, MandateKit, Behalf):
            for graph in graphs:
                for mode in LABEL_MODES:
                    rows.append(run_population(adapter, graph, mode))
            print(json.dumps({"completed_native": adapter.name, "rows": len(rows)}), flush=True)
        for fault in ("id_collision_at_depth", "label_indexed_revocation", "ignore_revocation"):
            for graph in graphs:
                for mode in LABEL_MODES:
                    rows.append(run_population(Behalf, graph, mode, fault))
            print(json.dumps({"completed_hand_selected_fault": fault, "rows": len(rows)}), flush=True)
    after_sources = source_state()
    if before_sources != after_sources or blocked_network_attempts:
        raise AssertionError("Source changed or an unexpected network operation was attempted")
    for row in rows:
        if row["fault"] == "none" and row["framework"] in ("mandatekit", "behalf"):
            assert all(row["probe_pass"].values()), row
    mutation_matrix = []
    for fault in ("id_collision_at_depth", "label_indexed_revocation", "ignore_revocation"):
        selected = [r for r in rows if r["fault"] == fault]
        valid_fault = any(not r["probe_pass"]["population_contract"] for r in selected)
        assert valid_fault and all(r["all_signatures_valid"] and r["all_before_allowed"] and
                                   r["credential_copy"]["before_allowed"] for r in selected)
        mutation_matrix.append({"framework": "behalf", "artificial_fault": fault,
            "cases": len(selected), "semantically_exposed_contract_fault": valid_fault,
            "all_pre_revocation_positive_controls_allow": all(r["all_before_allowed"] for r in selected),
            "detected_by_layer": {layer: any(not r["probe_pass"][layer] for r in selected) for layer in PROBE_LAYERS},
            "failing_cases_by_layer": {layer: sum(not r["probe_pass"][layer] for r in selected) for layer in PROBE_LAYERS}})
    audit_path = BASE / "results/apc/audit.json"
    depth_reference = None
    if audit_path.exists():
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        depth_reference = {"kind": "reference to prior executed saved audit, NOT rerun by this campaign",
            "source": "results/apc/audit.json", "sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            "depth_checks": audit["depth_ablation"]["checks"],
            "k_tuple_checks": audit["k_tuple_ablation"]["checks"]}
    result = {
        "title": "Small matched grant-graph population experiment",
        "metadata": {"python": platform.python_version(), "elapsed_seconds": time.perf_counter() - started,
                     "source_before_after_identical": before_sources == after_sources,
                     "blocked_network_attempts": len(blocked_network_attempts), "external_model_calls": 0,
                     "source": before_sources,
                     "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "contracts": {
            "independent_issue": "Separately issued grants are distinct even when subject/agent labels match.",
            "credential_copy": "A lossless copy of one credential remains one grant, with the same ID and revocation outcome.",
            "leaf_local_revocation": "Revoking a leaf denies that grant and its copies without denying unrelated grants.",
            "display_rename": "Model-level presentation alias only; credential and signed subject are untouched. SDK-native rename is NOT tested.",
            "depth": "Existing independently executed APC and MandateKit depth results are referenced, not newly mutation-tested here."},
        "probe_definitions": {
            "target_verdict": "All pre-revocation legal grants allow; after revoke only the selected target's DENY is asserted.",
            "target_condition": "The same target probe plus a revocation-specific denial category.",
            "population_contract": "Additional inputs/assertions: unique independent IDs, every unrelated grant still allows, and copied credential identity/outcome. This probe inspects more cases; no equal-cost superiority claim."},
        "topologies": [{k: v for k, v in g.items() if k != "nodes"} | {"nodes": len(g["nodes"])} for g in graphs],
        "label_modes": LABEL_MODES,
        "label_semantics": {
            "apc": "The exposed string is Principal.principal_id, a signed identity identifier, not a separate display label. Repetition means multiple issuance calls for the same principal; distinct strings mean distinct principals.",
            "mandatekit": "The issuance-time string is subject.agent_id; the independently generated grant ID is mandate_id.",
            "behalf": "The issuance-time string is the agent caveat; the grant is identified by its terminal chain ID.",
            "alpha_renamed_same_label": "A separately issued graph uses a consistently substituted subject string. This is not an SDK rename of an existing credential.",
            "cross_framework_match": "Graph topology and requested grant contracts are matched. The three APIs' identity/display-label models are not asserted equivalent."},
        "native_summary": {name: {
            "cases": sum(r["framework"] == name and r["fault"] == "none" for r in rows),
            "failing_cases_by_layer": {layer: sum(r["framework"] == name and r["fault"] == "none" and not r["probe_pass"][layer] for r in rows) for layer in PROBE_LAYERS},
        } for name in REPOS},
        "matched_population_table_same_label": [
            {key: r[key] for key in ("framework", "topology", "independently_issued_grants",
                 "unique_grant_ids", "total_denials_after_leaf_revocation", "off_target_denials")}
            for r in rows if r["fault"] == "none" and r["label_mode"] == "same_label"],
        "hand_selected_artificial_fault_matrix": mutation_matrix,
        "mutation_sensitivity_counts": {layer: {"detected": sum(r["detected_by_layer"][layer] for r in mutation_matrix),
                                                "hand_selected_faults": len(mutation_matrix)} for layer in PROBE_LAYERS},
        "within_condition_prior_run": depth_reference,
        "prior_art": {"aps_conformance_suite": "https://github.com/Agent-Authority-Conformance/aps-conformance-suite",
                      "close_fixture": "https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/fixtures/lifecycle-identifier-reuse-and-rename",
                      "relationship": "Lifecycle, identity, reason-specific conformance, paired vectors and mutation testing are prior art. This artifact adds only the explicit matched API population measurements and source-specific APC attribution."},
        "limits": [
            "Five small convenience-selected graph shapes, three label settings; these are not independent samples of deployments.",
            "Same-shape label transformations are correlated tests, not extra empirical prevalence evidence.",
            "Three hand-selected Behalf faults only; no representative mutation coverage or upstream-suite mutation score is claimed.",
            "Faults are artificial changes to issuance ID generation or a pluggable revocation store; they are not new Behalf vulnerabilities.",
            "No test-suite comparison: these are explicitly defined probe layers, not measurements of published SDK tests.",
            "The population probe sees more inputs than the target-only probes, so the sensitivity difference is expected coverage, not a new testing principle.",
            "Display alias renaming is out-of-band model metadata. Signed agent names are not edited; no native rename API was tested.",
            "APC principal_id and the other SDKs' subject/agent strings have different identity semantics; issuance-label variants are not a claim of physical identity equivalence.",
            "Native Behalf and MandateKit success is limited to these configured in-process grants and verification decisions, not an overall security ranking.",
            "Grant IDs, not physical AI-agent identities, are measured; stolen/copied credentials are not assumed to identify separate workers.",
            "No descendants-cascade contract is imposed on APC. Only leaf-local selectivity is tested.",
            "No live agent, service, transaction, network action or production exploit is involved."],
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "native_summary": result["native_summary"],
                      "artificial_fault_matrix": mutation_matrix,
                      "sensitivity": result["mutation_sensitivity_counts"]}, indent=2))


if __name__ == "__main__":
    main()
