#!/usr/bin/env python3
"""Vector figures for the auditable Phase 23 source-stage evaluation."""
import csv,collections,datetime as dt
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

R=Path(__file__).resolve().parent/'results'
F=Path(__file__).resolve().parents[1]/'figures'
F.mkdir(exist_ok=True)
rd=lambda n:list(csv.DictReader(open(R/n,encoding='utf8')))
attack=rd('attack_day_before_after.csv')
readiness=rd('readiness_sensitivity.csv')
alerts=rd('alert_ledger.csv')

def save(name):
 plt.savefig(F/(name+'.pdf'),bbox_inches='tight')
 plt.savefig(F/(name+'.png'),dpi=360,bbox_inches='tight')
 plt.close()

# Figure 1: pre-reference selected transactions (not full-day traffic)
labels=['Bacon proxy','Rari fETH','Rari fUSDC','Rari Comptroller']
fig,ax=plt.subplots(figsize=(8.4,3.6))
y=np.arange(len(labels));before=np.array([int(x['strictly_before']) for x in attack]);after=np.array([int(x['strictly_after']) for x in attack]);
ax.barh(y-0.14,before,height=0.28,label='Strictly before exploit')
ax.barh(y+0.14,before+1+after,height=0.28,alpha=0.5,label='Total selected on incident day')
ax.axvline(19,linestyle='--',linewidth=1.3,label='Minimum 19 prior observations')
ax.set_yticks(y,labels);ax.invert_yaxis();ax.set_xlabel('Distinct core-selected transactions');ax.set_xlim(0,55)
for k,v in enumerate(before):ax.text(v+.5,k-.14,str(v),va='center',fontsize=8)
for k,v in enumerate(before+after+1):ax.text(v+.5,k+.14,str(v),va='center',fontsize=8)
ax.legend(loc='lower right',fontsize=8);ax.set_title('Attack-time history feasibility versus end-of-day traffic')
fig.tight_layout();save('fig1_attack_time_selected')

# Figure 2: rank readiness fractions (no attack labels)
fig,ax=plt.subplots(figsize=(9.1,4.4))
keys=[('lifi_20220320','fixed-core'),('revest_20220327','fixed-core'),('bacon_20220305','proxy'),('rari_pool127_20220430','fETH'),('rari_pool127_20220430','fUSDC'),('rari_pool127_20220430','comptroller')]
marks={'daily_reset':'o','lookback_7d':'s','cumulative_in_window':'^'}
xs=np.arange(len(keys))
for mode,marker in marks.items():
 vals=[next(float(x['eligible_fraction']) for x in readiness if (x['case'],x['view'])==key and x['mode']==mode and int(x['min_prior_positive'])==19) for key in keys]
 ax.plot(xs,100*np.array(vals),marker=marker,linestyle='--',label={'daily_reset':'Daily reset','lookback_7d':'Trailing seven days','cumulative_in_window':'Captured 30-day history'}[mode])
ax.set_xticks(xs,['Li.Fi','Revest','Bacon','Rari fETH','Rari fUSDC','Rari Comptroller'],rotation=18,ha='right')
ax.set_ylabel('History-eligible selected transactions (%)');ax.set_ylim(bottom=0)
ax.set_title('Label-free readiness with 19 strictly preceding positive token outflows')
ax.legend(loc='upper left',fontsize=8)
fig.tight_layout();save('fig2_history_eligibility_six_views')

# Figure 3: relevant emitted notifications and their incident-relative timing
fig,ax=plt.subplots(figsize=(9,4.4))
join={('bacon_20220305','proxy'):'Bacon',('rari_pool127_20220430','fETH'):'Rari fETH',
 ('rari_pool127_20220430','fUSDC'):'Rari fUSDC',('lifi_20220320','fixed-core'):'Li.Fi',
 ('revest_20220327','fixed-core'):'Revest'}
case_dates={'bacon_20220305':dt.datetime(2022,3,5,12,46,23,tzinfo=dt.timezone.utc),
'rari_pool127_20220430':dt.datetime(2022,4,30,9,32,29,tzinfo=dt.timezone.utc),
'lifi_20220320':dt.datetime.fromtimestamp(1647744704,tz=dt.timezone.utc),
'revest_20220327':dt.datetime.fromtimestamp(1648345306,tz=dt.timezone.utc)}
labels=['Li.Fi cumulative','Revest 7d','Revest cumulative','Bacon cumulative','Rari fETH 7d',
        'Rari fETH cumulative','Rari fUSDC 7d','Rari fUSDC cumulative']
def lane(r):
 kind=join.get((r['case'],r['view']));return f'{kind} '+('7d' if r['mode']=='lookback_7d' else 'cumulative') if kind else None
for status,marker,label,size in [('UNADJUDICATED','o','Unadjudicated notification',38),
                                 ('VERIFIED_KNOWN_EXECUTION','*','Verified known execution',115)]:
 tx=[];yl=[]
 for r in alerts:
  l=lane(r)
  if l not in labels or r['reference_status']!=status:continue
  t=dt.datetime.fromisoformat(r['utc'].replace('Z','+00:00'))
  delta=(t-case_dates[r['case']]).total_seconds()/86400
  tx.append(delta);yl.append(labels.index(l))
 ax.scatter(tx,yl,marker=marker,s=size,alpha=.85,label=label)
ax.axvline(0,linestyle=':',linewidth=1.2)
ax.set_yticks(range(len(labels)),labels);ax.invert_yaxis();ax.set_xlabel('UTC days relative to known execution date/time')
ax.set_title('Verified execution hits (stars) and unadjudicated alerts (circles)')
ax.grid(axis='x',alpha=0.2);ax.legend(loc='upper left',fontsize=8)
fig.tight_layout();save('fig3_incident_relative_alerts')
print('FIGURES OK: 3 vector PDF and 3 360-dpi PNG')
