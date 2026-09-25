#!/usr/bin/env python3
from pathlib import Path
import json,statistics,random
r=Path(__file__).resolve().parent
d=r
assert json.loads((d/'network-status.json').read_text())['complete']
rows=[json.loads(s) for s in (d/'network-trials.jsonl').read_text().splitlines()]
rows=[x for x in rows if x['iteration']>=0]
groups={}
for x in rows:groups.setdefault((x['scenario'],x['suite']),{}).setdefault(x['implementation'],{})[x['iteration']]=x['rate']
out=[]
for (scenario,suite),variants in groups.items():
 entry=dict(scenario=scenario,suite=suite,variants={},comparisons={})
 for name,rs in variants.items():
  rates=list(rs.values())
  entry['variants'][name]=dict(n=len(rates),median=statistics.median(rates),cv_percent=100*statistics.stdev(rates)/statistics.mean(rates),minimum=min(rates),maximum=max(rates))
 for name,base in [('app-broad','app-current'),('app-fixed','app-current'),('app-fixed','app-broad')]:
  a,b=variants[base],variants[name]
  changes=[100*(b[i]/a[i]-1) for i in sorted(a)]
  rng=random.Random(250925)
  ci=sorted(statistics.median(rng.choices(changes,k=len(changes))) for _ in range(10000))
  entry['comparisons'][name+'_vs_'+base]=dict(paired_gain_percent=statistics.median(changes),ci95=[ci[250],ci[9750]])
 out.append(entry)
(r/'network-analysis.json').write_text(json.dumps(out,indent=2))
for x in out: print(json.dumps(x))
