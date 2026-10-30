#!/usr/bin/env python3
"""Rebuild the paper's exact 22-emitter census figure from audited unique days."""
import argparse,csv,json,hashlib
from pathlib import Path
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
BASE=Path(__file__).resolve().parent
PAPER=BASE.parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--audit',type=Path,default=BASE/'audit');p.add_argument('--out',type=Path,default=BASE/'audit/census_22_emitters.pdf');a=p.parse_args()
 old=json.loads((PAPER/'phase28/CANDIDATE_FRAME.json').read_text())['cases'];new=json.loads((BASE/'CANDIDATE_FRAME.json').read_text())['cases']
 order=[];names={}
 for c in old+new:
  if c['core_address'] not in order:order.append(c['core_address']);names[c['core_address']]=c['family']
 rows=list(csv.DictReader((a.audit/'COMBINED_UNIQUE_EMITTER_DAILY.csv').open()));groups=defaultdict(list)
 for r in rows:groups[r['core_address']].append(r)
 assert len(order)==22 and len(rows)==663
 short={'Compound cTUSD sweepToken':'Compound cTUSD','Umbrella Network staking':'Umbrella staking','Ronin Bridge Ethereum withdrawal':'Ronin bridge','Auctus options writer':'Auctus options writer','Beanstalk governance':'Beanstalk governance','Akutar NFT auction':'Akutar NFT auction','Saddle sUSD metapool':'Saddle sUSD metapool','ApeCoin airdrop claim':'ApeCoin airdrop','Inverse Finance June lending':'Inverse June lending','Schnoodle ERC777 token':'Schnoodle token','XCarnival XNFT':'XCarnival XNFT','FlippazOne NFT auction':'FlippazOne NFT auction','Omni NFT lending':'Omni NFT lending','Audius governance':'Audius governance','Nomad Bridge replica':'Nomad Replica','Bad Guys by RPF NFT':'Bad Guys NFT','Redacted Cartel wxBTRFLY':'Redacted wxBTRFLY','Harmony Ethereum multisig':'Harmony multisig','Circle PoC / Uniswap V2 DAI-USDC pair':'Circle DAI/USDC pair (33 d)','LuckyTiger NFT':'LuckyTiger NFT','XST token':'XST token','MEV badc0de bot':'MEV badc0de bot'}
 data=[]
 for core in order:
  nums=[int(x['tx']) for x in groups[core]];data.append({'core_address':core,'label':short[names[core]],'unique_days':len(nums),'below20_days':sum(n<20 for n in nums),'nonempty_below20_days':sum(0<n<20 for n in nums),'nonempty_days':sum(n>0 for n in nums),'selected_transaction_observations':sum(nums)})
 assert sum(r['below20_days'] for r in data)==516 and sum(r['nonempty_below20_days'] for r in data)==130
 plt.rcParams.update({'font.size':9,'font.family':'DejaVu Sans','pdf.fonttype':42,'ps.fonttype':42})
 fig,ax=plt.subplots(figsize=(6.7,8.0));ys=list(range(22));h=.32
 ax.barh([y-h/2 for y in ys],[r['below20_days'] for r in data],height=h,color='#1f77b4',label='All observed days with fewer than 20 TX')
 ax.barh([y+h/2 for y in ys],[r['nonempty_below20_days'] for r in data],height=h,color='#ff7f0e',label='Nonempty days with 1–19 TX')
 for y,r in enumerate(data):
  first=r['below20_days'];second=r['nonempty_below20_days']
  ax.text(first+.18,y-h/2,str(first),va='center',fontsize=7.4)
  if second>0:ax.text(second+.18,y+h/2,str(second),va='center',fontsize=7.4)
 ax.set_yticks(ys,[r['label'] for r in data]);ax.invert_yaxis();ax.set_xlim(0,33);ax.set_xticks(range(0,31,5));ax.set_xlabel('Unique observed UTC days per nominated emitter')
 ax.set_axisbelow(True);ax.grid(axis='x',alpha=.18);ax.tick_params(axis='y',length=0,pad=5)
 ax.axhline(15.5,color='#777777',linewidth=.6,linestyle=(0,(3,3)))
 ax.legend(loc='upper left',bbox_to_anchor=(0,-.055),frameon=False,fontsize=8.1)
 for s in ['top','right']:ax.spines[s].set_visible(False)
 fig.subplots_adjust(left=.35,right=.98,top=.99,bottom=.105)
 a.out.parent.mkdir(parents=True,exist_ok=True);fig.savefig(a.out,metadata={'Title':'Catalogue-complete source traffic census:22 nominated emitters','Creator':'Phase32 plot_census.py','CreationDate':None,'ModDate':None});plt.close(fig)
 digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 inputs={'plot_census.py':Path(__file__),'CANDIDATE_FRAME.json':BASE/'CANDIDATE_FRAME.json','phase28/CANDIDATE_FRAME.json':PAPER/'phase28/CANDIDATE_FRAME.json','audit/COMBINED_UNIQUE_EMITTER_DAILY.csv':a.audit/'COMBINED_UNIQUE_EMITTER_DAILY.csv','audit/CENSUS_AUDIT.json':a.audit/'CENSUS_AUDIT.json'}
 (a.out.with_suffix('.json')).write_text(json.dumps({'schema':'phase32_census_plot_binding_v1','unit':'Unique (core_address,UTC day); Circle windows merged before counting','rows':data,'all_unique_emitter_days':663,'all_nonempty_days':277,'all_nonempty_below20_days':130,'original16_then_new6_divider':True,'inputs_sha256':{k:digest(v) for k,v in inputs.items()},'output_pdf_sha256':digest(a.out),'matplotlib_version':matplotlib.__version__},indent=2,sort_keys=True)+'\n')
 print(a.out)
if __name__=='__main__':main()
