"""Independent specification checks; does not fit a model or alter the repository."""
from pathlib import Path
import argparse, dataclasses, hashlib, importlib.util, json, math, platform, random, subprocess, sys
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=Path(__file__).with_suffix('.json'))
args=parser.parse_args()
P=Path(__file__).resolve().parents[1]/'delayed_feedback.py'
spec=importlib.util.spec_from_file_location('independent_delayed_feedback',P);d=importlib.util.module_from_spec(spec);sys.modules[spec.name]=d;spec.loader.exec_module(d)
checks=[];view_count=plan_count=0
for delay in (0,1,2,4):
 for seed in range(20):
  rng=random.Random(seed);history=[d.LabelRecord(f'h{s}-{y}',s,y) for s in range(1,9) for y in (0,1)]
  q=d.DelayedLabelQueue(delay,start_step=9,initial_history=history)
  batches={s:[(f'{s}-{i}',rng.choice([0,1,None])) for i in range(rng.randrange(0,6))] for s in range(9,29)}
  order=list(batches);rng.shuffle(order)
  for s in order:q.register_step(s,[i for i,y in batches[s]],dict(batches[s]))
  saved=[]
  for t in range(9,34):
   v=q.begin_step(t);oracle={r.example_id:(r.source_step,r.label) for r in history}
   for s,rows in batches.items():
    if s+delay<t:oracle.update({i:(s,y) for i,y in rows})
   assert {r.example_id:(r.source_step,r.label) for r in v.records}==oracle
   assert all(r.released_after_step<t for r in v.records)
   assert not hasattr(v,'pending') and not hasattr(v,'_pending')
   p=d.plan_retraining(v,d.CalibrationRequirements(2,2))
   labelled_steps=sorted({s for s,y in oracle.values() if y is not None});expected_cal=labelled_steps[-4:]
   assert p.calibration_steps==tuple(expected_cal)
   expected_train={i for i,(s,y) in oracle.items() if y is not None and s not in expected_cal}
   expected_cal_ids={i for i,(s,y) in oracle.items() if y is not None and s in expected_cal}
   assert {r.example_id for r in p.train}==expected_train
   assert {r.example_id for r in p.calibration}==expected_cal_ids
   assert not expected_train & expected_cal_ids
   assert p.unknown_excluded==sum(y is None for s,y in oracle.values())
   saved.append((v,dataclasses.asdict(v)));q.end_step(t)
   assert all(dataclasses.asdict(old)==snapshot for old,snapshot in saved)
   view_count+=1;plan_count+=1
 checks.append({'check':'randomized_phase_and_partition_oracle','delay':delay,'seeds':20,'prediction_views':500,'pass':True})
# Prefix isolation under arbitrary changes to labels in later batches.
for delay in (0,1,2,4):
 outputs=[]
 for future_value in (0,1,None):
  q=d.DelayedLabelQueue(delay,start_step=1)
  for s in range(1,20):q.register_step(s,[str(s)],{str(s):(s%2 if s<10 else future_value)})
  prefix=[]
  for t in range(1,10+delay+1):prefix.append(q.begin_step(t));q.end_step(t)
  outputs.append(prefix)
 assert outputs[0]==outputs[1]==outputs[2]
checks.append({'check':'future_label_mutation_prefix_invariance','delays':[0,1,2,4],'pass':True})
# A genuine eligible plan, then malformed candidates with independent expected refusal.
history=[d.LabelRecord(f'{s}:{y}',s,y) for s in range(1,9) for y in (0,1)]
q=d.DelayedLabelQueue(4,start_step=9,initial_history=history);p=d.plan_retraining(q.begin_step(9),d.CalibrationRequirements(4,4))
assert p.eligible
old=d.ModelThresholdVersion('old','t-old',.61,'initial-history-declared')
def reg():return d.ModelThresholdRegistry(old)
def scores(model='new'):return [d.CalibrationScore(r.example_id,model,.9 if r.label else .1) for r in p.calibration]
def content_hash(plan):
 data={'prediction_step':plan.prediction_step,'requirements':dataclasses.asdict(plan.requirements),'train':[dataclasses.asdict(r) for r in plan.train],'calibration':[dataclasses.asdict(r) for r in plan.calibration],'unknown_excluded':plan.unknown_excluded}
 return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
future=dataclasses.replace(p,calibration=(dataclasses.replace(p.calibration[0],released_after_step=9),)+p.calibration[1:]);future=dataclasses.replace(future,plan_id=content_hash(future))
overlap=dataclasses.replace(p,train=p.train+p.calibration[:1]);overlap=dataclasses.replace(overlap,plan_id=content_hash(overlap))
mutations=[('old_model_scores',p,scores('old'),.5,'new','t-new'),('mixed_model_scores',p,scores()[:-1]+[dataclasses.replace(scores()[-1],model_version='old')],.5,'new','t-new'),('missing_score',p,scores()[:-1],.5,'new','t-new'),('duplicate_score',p,scores()+scores()[:1],.5,'new','t-new'),('unexpected_score',p,scores()+[d.CalibrationScore('absent','new',.2)],.5,'new','t-new'),('nan_score',p,[dataclasses.replace(scores()[0],score=float('nan'))]+scores()[1:],.5,'new','t-new'),('infinite_score',p,[dataclasses.replace(scores()[0],score=float('inf'))]+scores()[1:],.5,'new','t-new'),('failed_score',p,[dataclasses.replace(scores()[0],score=None)]+scores()[1:],.5,'new','t-new'),('nonfinite_threshold',p,scores(),float('nan'),'new','t-new'),('bool_threshold',p,scores(),True,'new','t-new'),('reuse_model_version',p,scores('old'),.5,'old','t-new'),('reuse_threshold_version',p,scores(),.5,'new','t-old'),('forged_identity',dataclasses.replace(p,plan_id='forged'),scores(),.5,'new','t-new'),('forged_future_release_with_valid_content_hash',future,scores(),.5,'new','t-new'),('overlap_with_valid_content_hash',overlap,scores(),.5,'new','t-new')]
for name,plan,ss,threshold,model,tver in mutations:
 r=reg();result=r.commit_candidate(model,plan,ss,threshold_version=tver,threshold=threshold)
 assert result.status=='skip_update',(name,result)
 assert result.active==old and r.active==old,(name,result)
 checks.append({'check':name,'pass':True,'skip_reasons':result.reasons})
r=reg();bad=r.commit_candidate('new',p,scores('old'),threshold_version='t-new',threshold=.5);good=r.commit_candidate('new',p,scores(),threshold_version='t-new',threshold=.5)
assert bad.status=='skip_update' and good.status=='installed' and r.active.model_version=='new' and r.active.threshold==.5
assert r.active.calibration_plan_id==p.plan_id
checks.append({'check':'failed_candidate_retry_installs_complete_new_pair_only_after_valid_calibration','pass':True})
# Frozen views are ordinary immutable dataclasses, not secure process isolation.
v=q.begin_step if False else d.PredictionView(9,())
try:v.prediction_step=99
except dataclasses.FrozenInstanceError:pass
else:raise AssertionError('PredictionView not frozen')
checks.append({'check':'prediction_view_frozen','pass':True})
# A valid earlier plan must never roll back a successfully installed version.
r=reg();r.commit_candidate('m9',p,[dataclasses.replace(x,model_version='m9') for x in scores()],threshold_version='t9',threshold=.5)
h=[d.LabelRecord(f'{s}:{y}',s,y) for s in range(1,8) for y in(0,1)]
q8=d.DelayedLabelQueue(0,start_step=8,initial_history=h);p8=d.plan_retraining(q8.begin_step(8),d.CalibrationRequirements(4,4))
z=r.commit_candidate('m8',p8,[d.CalibrationScore(x.example_id,'m8',.7 if x.label else .1) for x in p8.calibration],threshold_version='t8',threshold=.4)
stale_accepted=z.status=='installed'
assert z.status=='skip_update' and z.reasons==('stale_or_duplicate_activation_step',)
assert r.active.model_version=='m9' and r.active.threshold_version=='t9' and r.active.threshold==.5
assert r.last_activation_step==9
checks.append({'check':'valid_stale_candidate_cannot_roll_back_active_pair','pass':True,'skip_reasons':z.reasons})
same=r.commit_candidate('m9b',p,[dataclasses.replace(x,model_version='m9b') for x in scores()],threshold_version='t9b',threshold=.3)
assert same.status=='skip_update' and same.reasons==('stale_or_duplicate_activation_step',) and r.last_activation_step==9
checks.append({'check':'valid_same_step_candidate_cannot_replace_active_pair','pass':True,'skip_reasons':same.reasons})
report={'schema_version':'delayed_feedback_independent_review_v1','code_sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'review_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'python':sys.version,'platform':platform.platform(),'verdict':'PASS_FOR_BOOKKEEPING_SCOPE_WITH_INTEGRATION_LIMITS','queue_views_compared':view_count,'retraining_plans_compared':plan_count,'checks':checks,'all_checks_pass':True,'model_fitting_performed':False,'label_adjudication_performed':False,'verifier_mutates_source_or_inputs':False,'findings':[{'id':'DF01','severity':'resolved','finding':'Review initially demonstrated that a valid step8 plan could replace a model installed with a step9 plan. The narrow guard now requires strictly increasing declared activation steps; valid stale and same-step candidates retain the old pair.','observed_stale_plan_installed':stale_accepted,'remaining_boundary':'An optional initial_activation_step declares initial timing; when absent the first successful candidate establishes chronology. This checks declared ordering, not actual fitting, queue phase, wall-clock timing or estimator provenance. The reviewer implemented this narrow correction and reran the independent specification checks.'},{'id':'DF02','severity':'declared_limit','finding':'Available labels in initial_history are a separate warm-start assumption, including recent history regardless of online delay. This is explicitly documented; future experiments must declare which development/validation labels are already available.'},{'id':'DF03','severity':'definition','finding':'Calibration uses the latest four source steps with at least one known label; unknown-only steps do not count. This can extend the age span. Specify this exact choice and do not silently describe it as four consecutive stream steps.'},{'id':'DF04','severity':'declared_limit','finding':'Only the prediction-facing view omits future labels. Python queue internals store preloaded future labels; the API is not a security sandbox.'},{'id':'DF05','severity':'declared_limit','finding':'end_step attests that predictions were recorded; it does not verify a persisted decision journal. Integration must commit predictions before invoking release.'},{'id':'DF06','severity':'declared_limit','finding':'Registry checks version labels, cohort/timing/class constraints and whole-pair fallback; it cannot verify that actual estimator fitting excludes calibration rows or that supplied scores were produced by that estimator. No threshold-selection algorithm, estimator artifact, persistent update journal or real Elliptic execution is implemented by this utility.'}]}
out=args.output;out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'file':str(out),'views':view_count,'plans':plan_count,'checks':len(checks),'stale_plan_boundary':stale_accepted,'all_checks_pass':True}))
