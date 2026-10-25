"""Read-only full policy oracle from original selected logs; no production imports.

List/bisection count, direct release-instant counting, and token eligibility from
elapsed time since the last notification independently check all stored rows.
The implementation's rolling deque/refill mutation is deliberately not reused.
"""
import argparse
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import time
import zipfile

PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parents[1]
T = 86400 * 10**9
HOUR = 3600 * 10**9
CONFIG_SHA = '7b83aaa220f5527f58faf801fbc3977c657ef9f6a427d7523136694e0a41ea0d'
SOURCE_SHA = '549450dfc7db970ee039f17ef2c86d7a75820acc5b7128c46e340d1ebaf31726'
INPUT_SHA = '7505e42dec974609355d388313e7b446354f8c78a57421245e52b8107787431b'
ARCHIVE = None
RUNBASE = None


def binary_open(p):
    p = Path(p)
    if ARCHIVE is not None and p.is_relative_to(RUNBASE):
        return ARCHIVE.open(str(p.relative_to(RUNBASE)))
    return p.open('rb')


def gzip_text(p):
    return io.TextIOWrapper(gzip.GzipFile(fileobj=binary_open(p)))


def sha(p):
    h = hashlib.sha256()
    with binary_open(p) as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def load(p):
    with binary_open(p) as f:
        return json.load(f)


def equal(actual, expected, context):
    # JSON equality also checks bool/int distinction, missing fields and null.
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        if isinstance(actual, dict) and isinstance(expected, dict):
            changed = {k: [actual.get(k), expected.get(k)] for k in actual.keys() | expected.keys()
                       if json.dumps(actual.get(k), sort_keys=True) != json.dumps(expected.get(k), sort_keys=True)}
        else:
            changed = str(actual)[:500] + ' vs ' + str(expected)[:500]
        raise AssertionError((context, changed))


def day(t):
    return datetime.fromtimestamp(t//10**9, timezone.utc).date().isoformat()


def agg(rows):
    issued = [r for r in rows if r['notification_emitted']]
    return {'records': len(rows), 'accepted_events': sum(r['accepted'] for r in rows),
            'raw_triggers': sum(r['raw_trigger'] for r in rows),
            'group_candidates': sum(r['group_candidate'] for r in rows),
            'notifications': len(issued),
            'suppression_counts': dict(Counter(r['suppression_reason'] for r in rows if r['suppression_reason'] is not None)),
            'first_notification_time_ns': issued[0]['event_time_ns'] if issued else None,
            'last_notification_time_ns': issued[-1]['event_time_ns'] if issued else None}


def source_path(path):
    p = Path(path)
    if p.exists():
        return p
    # A sealed isolated-run manifest can retain its original /tmp layout.
    marker = '/data/raw/'
    assert marker in str(p), ('cannot resolve source', path)
    return ROOT / ('data/raw/' + str(p).split(marker, 1)[1])


def population_data(emitter, inputs, config):
    events, timestamps, seen, orders, previous_key = [], [], {}, {}, None
    for item in inputs:
        p = source_path(item['path'])
        assert sha(p) == item['sha256']
        assert p.stat().st_size == item['bytes']
        lines = p.read_text().splitlines()
        assert len(lines) == item['rows']
        for line in lines:
            e = json.loads(line)
            e['removed'] = e.get('removed')
            assert e['chain_id'] == emitter['chain_id'] and e['address'] == emitter['address']
            t = e['event_time_ns']
            assert type(t) is int and config['window']['start_ns'] <= t < config['window']['end_ns']
            assert day(t) == item['day_utc']
            assert e['observed_time'] is None and e['label_available_time'] is None and e['removed'] is None
            key = tuple(e[k] for k in ('block_number','transaction_index','log_index'))
            assert previous_key is None or key > previous_key
            assert not timestamps or t >= timestamps[-1]
            eid = 'event:' + digest([e['chain_id'],e['block_hash'],e['transaction_hash'],e['log_index']])
            assert eid not in seen
            fingerprint = digest({k:e[k] for k in ('chain_id','address','block_number','block_hash','transaction_index','transaction_hash','log_index','event_time_ns','topics','data','removed')})
            seen[eid] = fingerprint
            orders[':'.join(map(str,key))] = eid
            timestamps.append(t)
            score = len(timestamps)-bisect_right(timestamps,t-60*10**9)
            e['_event_id'],e['_score'] = eid,score
            events.append(e)
            previous_key = key
    return events,timestamps,seen,orders,previous_key


def audit_cell(run, config, emitter, policy, budget, inputs, pdata):
    events,timestamps,seen,orders,lastkey = pdata
    cid = f"{emitter['id']}__{policy}__B{budget}"
    cell = run/'cells'/cid
    c = dict(policy=policy,daily_budget=budget,window_start_ns=config['window']['start_ns'],
             window_end_ns=config['window']['end_ns'],address=emitter['address'],chain_id=emitter['chain_id'],**config['detector'])
    version = 'event_time_allocation_v1:'+digest(c)[:24]
    last = None
    counts = Counter()
    rows, aids, notification_ids = [], [], set()
    feature_hash = hashlib.sha256()
    with gzip_text(cell/'decisions.jsonl.gz') as f:
        for index,e in enumerate(events):
            actual = json.loads(next(f))
            t, eid, score = e['event_time_ns'],e['_event_id'],e['_score']
            date = day(t)
            quota = sum(j*T <= budget*(t % T) for j in range(budget)) if policy == 'paced_cumulative' else budget
            raw = score>=10
            candidate = raw and (last is None or t-last>=300*10**9)
            issued = False
            if not raw: reason = 'below_threshold'
            elif not candidate: reason = 'grouped'
            elif counts[date]>=budget: reason = 'budget'
            elif policy=='paced_cumulative' and counts[date]>=quota: reason = 'quota'
            elif policy=='token_bucket' and last is not None and budget*(t-last)<T: reason='token'
            else:
                reason=None
                issued=True
                last=t
                counts[date]+=1
            aid = 'alert:'+digest([version,eid]) if issued else None
            credit = (T if last is None else min(T,budget*(t-last))) if policy=='token_bucket' else None
            expected = {k:e[k] for k in ('chain_id','address','block_number','block_hash','transaction_hash','transaction_index','log_index','event_time_ns','observed_time','removed')}
            expected.update(schema_version='budget_policy_decision_v1',event_id=eid,policy_clock_ns=t,
                clock_domain='historical_event_time_ns_logical_simulation',label_used=False,policy=policy,
                policy_version=version,daily_budget=budget,accepted=True,score=score,raw_trigger=raw,
                group_candidate=candidate,notification_emitted=issued,notification_time_ns=t if issued else None,
                alert_id=aid,suppression_reason=reason,budget_day_utc=date,notifications_on_day=counts[date],
                daily_quota=quota,token_credit_units=credit,token_units_per_token=T if policy=='token_bucket' else None)
            equal(actual,expected,(cid,index))
            feature_hash.update(json.dumps([eid,score,raw],separators=(',',':')).encode()+b'\n')
            rows.append(expected)
            if issued:
                aids.append(aid)
                notification_ids.add(eid)
        assert f.read()=='', (cid,'extra rows')
    dates = [i['day_utc'] for i in inputs]
    byday = {d:[] for d in dates}
    byhour = {f'{d}T{h:02d}:00:00Z':[] for d in dates for h in range(24)}
    for row in rows:
        d=day(row['event_time_ns'])
        byday[d].append(row)
        byhour[f"{d}T{row['event_time_ns']%T//HOUR:02d}:00:00Z"].append(row)
    daily=[dict(day_utc=d,**agg(rs),daily_budget=budget,unused_daily_slots=budget-len([r for r in rs if r['notification_emitted']]),at_cap=len([r for r in rs if r['notification_emitted']])==budget) for d,rs in byday.items()]
    hourly=[dict(hour_utc=h,**agg(rs)) for h,rs in byhour.items()]
    equal(load(cell/'daily.json'),daily,(cid,'all 30 daily aggregates'))
    equal(load(cell/'hourly.json'),hourly,(cid,'all 720 hourly aggregates'))
    endtime = timestamps[-1] if timestamps else config['window']['start_ns']
    endwindow = timestamps[bisect_right(timestamps,endtime-60*10**9):]
    expected_state = dict(schema_version='budget_policy_state_v1',config=c,seen=seen,order_keys=orders,
        watermark=list(lastkey) if lastkey else None,window=endwindow,policy_clock_ns=endtime,
        last_emitted_time_ns=last,daily_counts=dict(counts),
        token_credit_units=(T if last is None else min(T,budget*(endtime-last))) if policy=='token_bucket' else T,
        alert_ids=aids)
    with gzip_text(cell/'final_state.json.gz') as f:
        equal(json.load(f),expected_state,(cid,'entire final state'))
    summary=load(cell/'summary.json')
    expected_summary=dict(cell_id=cid,population_id=emitter['id'],policy=policy,daily_budget=budget,
        primary_budget=budget==config['primary_budget'],**agg(rows),unknown_observed_time=len(rows),
        unknown_removed=len(rows),days=30,hard_cap_exceedances=0,unique_alert_ids=len(set(aids)),
        days_at_cap=sum(d['at_cap'] for d in daily),unused_daily_slots=sum(d['unused_daily_slots'] for d in daily),
        raw_trigger_active_hours=sum(h['raw_triggers']>0 for h in hourly),
        raw_trigger_active_hours_with_notification=sum(h['raw_triggers']>0 and h['notifications']>0 for h in hourly),
        accepted_feature_stream_sha256=feature_hash.hexdigest(),identity_ledger_entries=len(seen),
        order_key_ledger_entries=len(orders),window_entries_at_end=len(endwindow),
        decision_log=dict(path=f'cells/{cid}/decisions.jsonl.gz',sha256=sha(cell/'decisions.jsonl.gz'),rows=len(rows)),
        artifacts={n:sha(cell/n) for n in ('daily.json','decisions.jsonl.gz','final_state.json.gz','hourly.json')},
        state_semantics='finite-horizon exact identity/order ledgers; orderly checkpoint, no crash-safe delivery')
    equal(summary,expected_summary,(cid,'complete summary'))
    assert all(d['notifications']<=budget for d in daily)
    if policy=='token_bucket':
        emitted_times=[r['event_time_ns'] for r in rows if r['notification_emitted']]
        assert all(budget*(b-a)>=T for a,b in zip(emitted_times,emitted_times[1:]))
    return expected_summary, notification_ids


def main():
    global ARCHIVE, RUNBASE
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,required=True)
    ap.add_argument('--seal',type=Path,required=True,help='Read every run artifact directly from this immutable ZIP')
    ap.add_argument('--output',type=Path,default=Path(__file__).with_suffix('.json'))
    args=ap.parse_args()
    start=time.perf_counter()
    run=args.run.resolve()
    RUNBASE = run
    seal_sha = sha(args.seal)
    ARCHIVE = zipfile.ZipFile(args.seal)
    member_manifest = json.loads(ARCHIVE.read('sealed_member_manifest.json'))
    assert len(ARCHIVE.namelist()) == len(set(ARCHIVE.namelist()))
    assert set(ARCHIVE.namelist()) == set(member_manifest['members']) | {'sealed_member_manifest.json'}
    for name, info in member_manifest['members'].items():
        assert ARCHIVE.getinfo(name).file_size == info['bytes']
        assert sha(run/name) == info['sha256'], ('sealed member hash', name)
    manifest=load(run/'run_manifest.json')
    assert manifest['status']=='complete', 'failed or partial runs cannot be accepted'
    assert manifest['frozen_sources_config_inputs_unchanged'] is True
    config=load(run/'config.json')
    assert sha(run/'config.json')==CONFIG_SHA
    assert sha(run/'source_snapshot/budget_policy_replay.py')==SOURCE_SHA
    assert sha(run/'input_manifest.json')==INPUT_SHA
    frozen_hashes={p:sha(run/p) for p in manifest['frozen_file_sha256']}
    equal(frozen_hashes,manifest['frozen_file_sha256'],'all frozen files')
    inputs=load(run/'resolved_inputs.json')
    summaries,sets=[],{}
    input_counts={}
    for emitter in config['emitters']:
        items=inputs[emitter['id']]
        assert len(items)==30
        pdata=population_data(emitter,items,config)
        input_counts[emitter['id']]=len(pdata[0])
        for budget in config['budgets']:
            for policy in config['policies']:
                summary,ids=audit_cell(run,config,emitter,policy,budget,items,pdata)
                summaries.append(summary)
                sets[summary['cell_id']]=ids
                print('PASS',summary['cell_id'],summary['records'],flush=True)
    stored=load(run/'study_summary.json')
    equal(stored['cells'],summaries,'all study summaries')
    assert stored['status']=='complete' and stored['labels_used'] is False and stored['raw_feature_streams_identical'] is True
    overlaps=[]
    for e in config['emitters']:
        relevant=[s for s in summaries if s['population_id']==e['id']]
        assert len({s['accepted_feature_stream_sha256'] for s in relevant})==1
        for budget in config['budgets']:
            selected=[s for s in relevant if s['daily_budget']==budget]
            for i,a in enumerate(selected):
                for b in selected[i+1:]:
                    x,y=sets[a['cell_id']],sets[b['cell_id']]
                    overlaps.append(dict(population_id=e['id'],daily_budget=budget,policy_a=a['policy'],policy_b=b['policy'],notifications_a=len(x),notifications_b=len(y),intersection=len(x&y),union=len(x|y),jaccard=len(x&y)/len(x|y) if x|y else None))
    equal(stored['notification_set_overlap'],overlaps,'all notification overlaps')
    assert frozen_hashes=={p:sha(run/p) for p in frozen_hashes}
    result=dict(status='PASS',run=str(run),config_sha256=CONFIG_SHA,source_sha256=SOURCE_SHA,input_manifest_sha256=INPUT_SHA,
        input_records=input_counts,decision_rows=sum(s['records'] for s in summaries),cells=len(summaries),
        daily_aggregates=30*len(summaries),hourly_aggregates=720*len(summaries),entire_final_states=18,
        frozen_files=len(frozen_hashes),source_input_files=60,cell_artifact_hashes=72,gzip_streams_read_through_eof=36,
        checks=['every decision field and exact type from original source logs','independent bisection count in (t-60s,t]','explicit paced-release counting','capacity-one token eligibility from time since last emission','per-policy emitted-anchor grouping','hard UTC-day cap; token credit does not reset at midnight','all daily/hourly aggregates including zeros','entire final state including identities, fingerprints, order keys, window, clock, token and alert IDs','all summary fields and 18 set-overlap comparisons','raw feature hash invariant across nine policies/budgets per emitter','all source selected-file hashes and frozen provenance hashes'],
        limitations=['Historical event-time logical simulation; observed delivery timestamps and removed flags are unknown.','The same detector has policy-dependent grouping because only emitted notifications move its anchor.','This audit does not reinterpret labels or claim detection/generalization, timing or crash-safe delivery.','A separate independent integrity report verifies sealed ZIP and copied loose-file equality.'],
        summaries=summaries,notification_set_overlap=overlaps,wall_seconds=time.perf_counter()-start,
        auditor_sha256=sha(__file__),seal_path=str(args.seal.resolve()),seal_sha256=seal_sha,
        sealed_members=len(ARCHIVE.namelist()),run_artifacts_read_directly_from_seal=True)
    assert sha(args.seal)==seal_sha
    ARCHIVE.close()
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:result[k] for k in ('status','cells','decision_rows','wall_seconds')}))


if __name__=='__main__':
    main()
