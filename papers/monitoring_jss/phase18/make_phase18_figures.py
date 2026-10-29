#!/usr/bin/env python3
"""Figures and label-free daily token traffic for Phase18. No model imports."""
import argparse, collections, csv, json, zipfile
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

CASES=('lifi_20220320','revest_20220327')
MODES=('daily_reset','lookback_7d','cumulative_in_window')
LABELS=('UTC daily reset','Trailing 7 days','History since start')

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--evidence-zip',type=Path,required=True);ap.add_argument('--results',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 r=json.loads((a.results/'full_replay_summary.json').read_text())
 with zipfile.ZipFile(a.evidence_zip) as z:
  token_days=[]; day_counts=[]
  for case in CASES:
   by_day=collections.Counter(); token_pos=collections.Counter()
   prefix=f'runtime/attempt2/observations/{case}/'
   for name in sorted(n for n in z.namelist() if n.startswith(prefix) and n.endswith('.jsonl')):
    day=name.rsplit('/',1)[-1][:-6]
    for line in z.read(name).splitlines():
     ob=json.loads(line);by_day[day]+=1
     for flow in ob['token_flows']:
      if int(flow['external_out_raw'])>0:token_pos[day,flow['token_address']]+=1
   for (day,token),n in sorted(token_pos.items()):token_days.append({'case':case,'day':day,'token':token,'positive_outflow_transactions':n,'eligible_scores_for_token_day':max(0,n-19)})
   for day in sorted(by_day):day_counts.append({'case':case,'day':day,'selected_transactions':by_day[day]})
 def writecsv(name,items):
  with (a.out/name).open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(items[0]));w.writeheader();w.writerows(items)
 writecsv('token_day_applicability.csv',token_days)
 writecsv('selected_daily_activity.csv',day_counts)
 def get(c,m):
  return next(x for x in r['cell_summaries'] if x['case']==c and x['initialization']==m and x['method']=='outflow_rank_1_20' and x['policy']=='greedy' and x['daily_budget']==5)
 # Figure 1. Conditional history-eligibility necessary condition per token/day.
 fig,axs=plt.subplots(1,2,figsize=(11,4),sharey=False)
 for ax,case in zip(axs,CASES):
  counts=sorted(x['positive_outflow_transactions'] for x in token_days if x['case']==case)
  xs=list(range(1,len(counts)+1))
  ax.scatter(xs,counts,s=17,alpha=.75)
  ax.axhline(20,linestyle='--',linewidth=1.2,label='First eligible score requires 20 observations')
  ax.set_title('Li.Fi' if case.startswith('lifi') else 'Revest')
  ax.set_xlabel('Token-day, ordered by positive-outflow count')
  ax.set_ylabel('Positive outflow observations in token-day')
  ax.set_ylim(bottom=0)
  ax.grid(axis='y',alpha=.25)
 axs[0].legend(fontsize=7,loc='upper left')
 fig.suptitle('Token-level daily traffic vs minimum history gate')
 fig.tight_layout(rect=(0,0,1,.93));fig.savefig(a.out/'fig1_token_day_gate.png',dpi=180);fig.savefig(a.out/'fig1_token_day_gate.svg');plt.close(fig)
 # Fig 2. Strictly past history ablation, selected transaction eligibility.
 fig,ax=plt.subplots(figsize=(9.2,4.4))
 x=list(range(3));delta=.34
 for offset,case,title in [(-delta/2,CASES[0],'Li.Fi'),(delta/2,CASES[1],'Revest')]:
  ys=[100*get(case,m)['eligible_tx']/get(case,m)['selected_tx'] for m in MODES]
  rect=ax.bar([a+offset for a in x],ys,delta,label=title)
  for b,y in zip(rect,ys):ax.text(b.get_x()+b.get_width()/2,y+.6,f'{y:.1f}%',ha='center',fontsize=9)
 ax.set_xticks(x,LABELS);ax.set_ylim(0,45);ax.set_ylabel('Selected transactions with eligible token score (%)');ax.legend();ax.grid(axis='y',alpha=.2);ax.set_title('Retaining historical data improves score eligibility')
 fig.tight_layout();fig.savefig(a.out/'fig2_history_eligibility.png',dpi=180);fig.savefig(a.out/'fig2_history_eligibility.svg');plt.close(fig)
 # Fig3. Raw triggers and actual emitted alert, primary 1/20 B5 greedy.
 fig,axs=plt.subplots(1,2,figsize=(11.5,4.4),sharey=True)
 for ax,case in zip(axs,CASES):
  vals=[get(case,m) for m in MODES]
  p=ax.bar([a-.15 for a in x],[v['raw_triggers'] for v in vals],.3,label='Raw triggers')
  q=ax.bar([a+.15 for a in x],[v['notifications'] for v in vals],.3,label='Emitted notifications')
  for b in list(p)+list(q):ax.text(b.get_x()+b.get_width()/2,b.get_height()+.05,str(int(b.get_height())),ha='center',fontsize=9)
  ax.set_title('Li.Fi' if case.startswith('lifi') else 'Revest')
  ax.set_xticks(x,LABELS);ax.tick_params(axis='x',labelrotation=12)
  ax.set_ylabel('Transactions')
  ax.set_ylim(0,4)
  ax.grid(axis='y',alpha=.2)
 axs[0].legend(fontsize=8,loc='upper left');fig.suptitle('Rank 1/20: full replay at B=5, greedy (known execution hits = 0)')
 fig.tight_layout(rect=(0,0,1,.92));fig.savefig(a.out/'fig3_raw_vs_notifications.png',dpi=180);fig.savefig(a.out/'fig3_raw_vs_notifications.svg');plt.close(fig)
 print('Rendered 3 figures; token-days',len(token_days))
if __name__=='__main__': main()
