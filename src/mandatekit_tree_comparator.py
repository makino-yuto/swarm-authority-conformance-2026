"""Unmodified MandateKit branching/leaf-revocation comparator.

A three-way signed tree through depth three, SDK-generated UUID mandate IDs,
and fresh issuer-signed revocation lists. This tests local leaf isolation
under caller-supplied list snapshots, not revocation distribution or global
production security. No transactions, model calls or network services run.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from mandatekit_comparator import ROOT,REPO,PINNED

OUTPUT = ROOT/'results'/'apc'/'mandatekit_tree_comparator.json'
NOW = datetime(2026,11,6,0,0,tzinfo=timezone.utc)


def run(width=3,depth=3):
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    if commit != PINNED:
        raise RuntimeError(f'Unexpected upstream commit {commit}')
    if subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True).strip():
        raise RuntimeError('MandateKit checkout has local changes')
    sys.path.insert(0,str(REPO/'python'))
    from mandatekit import (
        build_mandate,delegate_mandate,sign_mandate,verify_signature,verify,
        build_revocation_list,sign_revocation_list,verify_revocation_list_signature,
    )
    import mandatekit
    from mandatekit.signing import _public_from_seed,_BACKEND

    def seed(path):
        return hashlib.sha256(('synthetic-mandatekit-tree/'+path).encode()).digest()

    owner_seed=seed('human-owner')
    root_agent_seed=seed('r')
    root_list_id='synthetic-issuer-list/human-owner'
    root_signed=sign_mandate(build_mandate(
        agent_id='synthetic-agent/r',agent_public_key=_public_from_seed(root_agent_seed),
        categories=['synthetic-category'],merchants={'allow':['synthetic-merchant']},
        max_amount={'value':0,'currency':'USD'},actions=['read'],
        delegation={'max_depth':depth},
        revocation={'list_id':root_list_id,'max_age_seconds':3600},
        issued_at=NOW-timedelta(minutes=10),expires_at=NOW+timedelta(hours=1),
        # mandate_id intentionally omitted: exercise the SDK's UUID default.
    ),owner_seed)
    levels=[[{'path':'r','level':0,'signed':root_signed,'subject_seed':root_agent_seed,'issuer_list_id':root_list_id}]]
    list_signers={root_list_id:owner_seed}
    for level in range(1,depth+1):
        children=[]
        for parent in levels[-1]:
            for branch in range(width):
                path=parent['path']+'.'+str(branch)
                subject_seed=seed(path)
                list_id='synthetic-issuer-list/'+parent['path']
                list_signers[list_id]=parent['subject_seed']
                child=sign_mandate(delegate_mandate(
                    parent['signed'],agent_id='synthetic-agent/'+path,
                    agent_public_key=_public_from_seed(subject_seed),max_depth=depth-level,
                    revocation={'list_id':list_id,'max_age_seconds':3600},
                    issued_at=NOW-timedelta(minutes=10),expires_at=NOW+timedelta(hours=1),
                    # mandate_id intentionally omitted here too.
                ),parent['subject_seed'])
                children.append({'path':path,'level':level,'signed':child,'subject_seed':subject_seed,'issuer_list_id':list_id})
        levels.append(children)
    nodes=[node for group in levels for node in group]
    txn={'action':'read','merchant':'synthetic-merchant','category':'synthetic-category','amount':{'value':0,'currency':'USD'}}
    trusted_key=root_signed['signature']['public_key']
    target=levels[-1][0]
    target_id=target['signed']['mandate']['mandate_id']

    def lists(revoke_target):
        return [sign_revocation_list(build_revocation_list(
            list_id=list_id,
            revoked=[target_id] if revoke_target and list_id==target['issuer_list_id'] else [],
            issued_at=NOW-timedelta(minutes=1),
        ),signer) for list_id,signer in sorted(list_signers.items())]

    empty_lists=lists(False)
    revoked_lists=lists(True)
    before=[]
    after=[]
    for node in nodes:
        b=verify(node['signed'],txn,now=NOW,trusted_keys=[trusted_key],revocation_lists=empty_lists)
        a=verify(node['signed'],txn,now=NOW,trusted_keys=[trusted_key],revocation_lists=revoked_lists)
        record={'path':node['path'],'level':node['level'],'mandate_id':node['signed']['mandate']['mandate_id']}
        before.append({**record,'decision':b['decision'],'signature_valid':b['signature_valid'],'failed':b['failed']})
        after.append({**record,'decision':a['decision'],'signature_valid':a['signature_valid'],'failed':a['failed']})
    ids=[n['signed']['mandate']['mandate_id'] for n in nodes]
    per_level=[{
        'level':i,'envelopes':len(group),
        'unique_ids':len({n['signed']['mandate']['mandate_id'] for n in group}),
        'baseline_admitted':sum(r['decision']=='allow' for r in before if r['level']==i),
        'denied_after_one_leaf_revocation':sum(r['decision']=='deny' for r in after if r['level']==i),
    } for i,group in enumerate(levels)]
    denied=[r for r in after if r['decision']=='deny']
    checks={
        'expected_tree_node_count':len(nodes)==sum(width**i for i in range(depth+1)),
        'all_ids_unique':len(set(ids))==len(nodes),
        'all_raw_node_signatures_valid':all(verify_signature(n['signed']) for n in nodes),
        'all_revocation_list_signatures_valid':all(verify_revocation_list_signature(l) for l in empty_lists+revoked_lists),
        'all_baseline_admitted':all(r['decision']=='allow' for r in before),
        'only_target_leaf_denied':len(denied)==1 and denied[0]['mandate_id']==target_id,
        'target_denial_is_revocation':len(denied)==1 and any(f['constraint']=='revoked' for f in denied[0]['failed']),
        'all_unrelated_nodes_still_admitted':all(r['decision']=='allow' for r in after if r['mandate_id']!=target_id),
        'all_output_signature_flags_remain_valid':all(r['signature_valid'] for r in before+after),
    }
    return {
        'repository':'https://github.com/major-matters/mandatekit','commit':commit,
        'sdk_version':mandatekit.__version__,'crypto_backend':_BACKEND,
        'width':width,'depth':depth,'total_envelopes':len(nodes),'unique_ids_total':len(set(ids)),
        'id_generation':'Unchanged build_mandate/delegate_mandate UUID defaults; caller supplied no mandate_id.',
        'fixed_now':NOW.isoformat(),'revocation_list_count':len(list_signers),
        'revoked_target':{'path':target['path'],'mandate_id':target_id,'issuer_list_id':target['issuer_list_id']},
        'per_level':per_level,'before_revocation':before,'after_one_leaf_revocation':after,
        'checks':checks,'all_checks_pass':all(checks.values()),
        'source_sha256':{p:hashlib.sha256((REPO/p).read_bytes()).hexdigest() for p in [
            'python/mandatekit/mandate.py','python/mandatekit/verifier.py','python/mandatekit/signing.py',
        ]},
        'source_locations':{
            'sdk_default_uuid':'python/mandatekit/mandate.py:326 and :395',
            'remaining_depth_validation':'python/mandatekit/verifier.py:607-613',
            'revocation_list_signer_check':'python/mandatekit/verifier.py:402-407',
            'exact_mandate_id_revocation_match':'python/mandatekit/verifier.py:418-422',
            'revocation_checks_each_chain_link':'python/mandatekit/verifier.py:937-942',
        },
        'scope_limits':[
            'Local synthetic signed-grant verification only; no real agent behavior or transactions are measured.',
            'Revocation lists are complete, fresh, issuer-signed snapshots supplied by this fixture. Distribution, rollback, stale-list replay, multi-process synchronization and production operation are not evaluated.',
            'This matches the APC leaf-local isolation question, where the selected node has no descendants; ancestor-cascade semantics are not compared.',
            'The SDK uses a remaining-depth value at every signed link; this is not APC session-state accounting.',
            'Mandate IDs are random UUIDs generated by unchanged SDK APIs. Exact ID bytes change on re-run; verdict invariants and counts are expected to remain the same.',
            'Experimental unaudited v0 SDK using its pure-Python crypto fallback in this environment; not a production-security endorsement.',
        ],
    }


def main():
    sys.stdout.reconfigure(encoding='utf8')
    result=run()
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ['commit','width','depth','total_envelopes','unique_ids_total','revocation_list_count','per_level','checks','all_checks_pass']},indent=2))
    print('saved',OUTPUT)
    if not result['all_checks_pass']:raise SystemExit(1)


if __name__=='__main__':main()
