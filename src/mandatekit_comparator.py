"""Pinned, unchanged-API MandateKit depth comparator; local synthetic mandates only.

Runs the two documented standalone Python suites and a legal/over-depth
2x2 fixture. This is a narrow external comparator, not an overall ranking of
MandateKit and APC. No models, live funds, or network services are called.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / 'alternatives' / 'mandatekit'
PINNED = 'fc6a3745ef3eab5ee1e8842f275a5666cf9ffc4f'
OUTPUT = ROOT / 'results' / 'apc' / 'mandatekit_comparator.json'


def upstream_tests():
    results = []
    for rel in ['tests/test_mandatekit.py', 'tests/test_v02.py']:
        code = 'import sys,runpy; sys.path.insert(0,"."); runpy.run_path(' + repr(rel) + ',run_name="__main__")'
        cmd = [sys.executable, '-B', '-c', code]
        p = subprocess.run(cmd, cwd=REPO / 'python', text=True, encoding='utf8', errors='replace', capture_output=True, timeout=120)
        matches = re.findall(r'(\d+)/(\d+) passed', p.stdout)
        results.append({
            'suite': 'python/' + rel,
            'command': cmd,
            'cwd': str(REPO / 'python'),
            'returncode': p.returncode,
            'passed': int(matches[-1][0]) if matches else None,
            'total': int(matches[-1][1]) if matches else None,
            'stdout': p.stdout,
            'stderr': p.stderr,
        })
        print(json.dumps({'suite': rel, 'returncode': p.returncode, 'summary': matches[-1] if matches else None}), flush=True)
    return results


def depth_matrix():
    sys.path.insert(0, str(REPO / 'python'))
    from mandatekit import build_mandate, delegate_mandate, sign_mandate, verify_signature, verify
    import mandatekit
    from mandatekit.signing import _public_from_seed, _BACKEND

    # Public-key derivation is only fixture preparation, matching upstream tests.
    # Builders, signatures and every decision use unchanged upstream functions.
    issuer_seed = bytes(range(32))
    worker_seed = bytes(range(32,64))
    grandchild_signer_seed = bytes(range(64,96))
    worker_public = _public_from_seed(worker_seed)
    grandchild_signer_public = _public_from_seed(grandchild_signer_seed)
    now = datetime(2026,11,6,0,0,tzinfo=timezone.utc)
    transaction = {'action':'read','merchant':'synthetic-merchant','category':'synthetic-category','amount':{'value':0,'currency':'USD'}}
    cases = []
    for cap in [1,2]:
        for actual_depth in [1,2]:
            root = sign_mandate(build_mandate(
                agent_id='synthetic-worker', agent_public_key=worker_public,
                categories=['synthetic-category'], merchants={'allow':['synthetic-merchant']},
                max_amount={'value':0,'currency':'USD'}, actions=['read'],
                delegation={'max_depth':cap},
                issued_at=now-timedelta(hours=1), expires_at=now+timedelta(hours=1),
                mandate_id=f'fixture-root-cap-{cap}',
            ), issuer_seed)
            mid = sign_mandate(delegate_mandate(
                root, agent_id='synthetic-next-worker', agent_public_key=grandchild_signer_public,
                max_depth=cap-1, issued_at=now-timedelta(hours=1),
                expires_at=now+timedelta(hours=1), mandate_id=f'fixture-mid-cap-{cap}',
            ), worker_seed)
            chain = [root,mid]
            signed = mid
            if actual_depth == 2:
                signed = sign_mandate(delegate_mandate(
                    mid, agent_id='synthetic-leaf', issued_at=now-timedelta(hours=1),
                    expires_at=now+timedelta(hours=1), mandate_id=f'fixture-leaf-cap-{cap}',
                ), grandchild_signer_seed)
                chain.append(signed)
            trusted_key = root['signature']['public_key']
            v = verify(signed, transaction, now=now, trusted_keys=[trusted_key])
            cases.append({
                'root_max_delegation_depth':cap,
                'actual_delegation_edges':actual_depth,
                'root_subject_remaining_depth':cap,
                'mid_subject_remaining_depth':cap-1,
                'all_link_signatures_valid':all(verify_signature(link) for link in chain),
                'expected_decision':'allow' if actual_depth <= cap else 'deny',
                'decision':v['decision'], 'signature_valid':v['signature_valid'],
                'failed':v['failed'], 'matched':v['matched'], 'rationale':v['rationale'],
            })
    checks = {
        'all_raw_link_signatures_valid':all(c['all_link_signatures_valid'] for c in cases),
        'all_expected_decisions_match':all(c['decision']==c['expected_decision'] for c in cases),
        'three_legal_cases_allow':sum(c['decision']=='allow' for c in cases)==3,
        'over_depth_case_denies':next(c for c in cases if c['root_max_delegation_depth']==1 and c['actual_delegation_edges']==2)['decision']=='deny',
        'over_depth_reason_is_delegation':any(
            f['constraint']=='delegation' and 'does not allow delegation' in f.get('detail','')
            for c in cases if c['root_max_delegation_depth']==1 and c['actual_delegation_edges']==2
            for f in c['failed']
        ),
    }
    return {'sdk_version':mandatekit.__version__,'crypto_backend':_BACKEND,'fixed_now':now.isoformat(),'transaction':transaction,'cases':cases,'checks':checks}


def main():
    sys.stdout.reconfigure(encoding='utf8')
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    if commit != PINNED:
        raise RuntimeError(f'Unexpected MandateKit commit {commit}')
    status = subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True).strip()
    if status:
        raise RuntimeError('MandateKit checkout has local changes')
    suites = upstream_tests()
    matrix = depth_matrix()
    source_files = ['python/mandatekit/mandate.py','python/mandatekit/verifier.py','python/mandatekit/signing.py','python/tests/test_mandatekit.py','python/tests/test_v02.py','README.md','LICENSE']
    result = {
        'repository':'https://github.com/major-matters/mandatekit',
        'commit':commit,'python':platform.python_version(),
        'source_sha256':{p:hashlib.sha256((REPO/p).read_bytes()).hexdigest() for p in source_files},
        'upstream_standalone_tests':suites,
        'depth_comparator':matrix,
        'scope_limits':[
            'Experimental unaudited v0 SDK; this is not a production-security endorsement.',
            'Only the documented Python core/v0.2 standalone suites were run; not TypeScript, optional property tests, MCP proxy or model integrations.',
            'The comparator tests delegation-edge depth only. MandateKit uses a remaining-depth budget at each signed link; APC models a session budget tracker. No overall system ranking is supported.',
            'The negative fixture has valid cryptographic signatures and trusted root key, but a prohibited extra delegation edge. It is not a signature forgery.',
            'On a failed chain walk, issuer_trusted also fails because root_key is unset; this is a downstream consequence of the delegation failure, not an independently planted wrong issuer.',
            'The fixture uses public build/delegate/sign/verify APIs unchanged; the internal public-key helper is used only to prepare deterministic synthetic test keys, as upstream tests do.',
            'No transactions were executed; results concern local verification decisions.',
        ],
        'all_checks_pass':all(s['returncode']==0 for s in suites) and all(matrix['checks'].values()),
    }
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'output':str(OUTPUT),'commit':commit,'sdk_version':matrix['sdk_version'],'all_checks_pass':result['all_checks_pass'],'depth_matrix':[{k:c[k] for k in ['root_max_delegation_depth','actual_delegation_edges','expected_decision','decision','all_link_signatures_valid']} for c in matrix['cases']]},ensure_ascii=False,indent=2))
    if not result['all_checks_pass']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
