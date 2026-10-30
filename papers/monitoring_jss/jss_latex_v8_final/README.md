# Article 2 — JSS revision V8

**Title:** When Can a Blockchain Monitor Make a Decision? Source-Audited Feature Readiness, Historical State, and Exact-Execution Evidence.

The release identifier is [`article2-jss-v8-2026-10-30`](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/tree/article2-jss-v8-2026-10-30). The accompanying release manifest identifies the source commit and the SHA-256 of every packaged file. The published V7 release remains unchanged at commit `aab963c5c5aa60adb7af5f04bc86601f92c67b87`; its manuscript, source and exact package bytes were verified before this revision.

## Baselines and scientific units

The V6.1 baseline remains `article2-jss-v6.1-2026-10-29`, commit `651daa926bb3803ad76227389a4fb35c1027da63`. The V6 research line branched from Phase27 commit `78baeb5c83a931a9f3f85e56893391f94cd0699b`, as verified by the parent of nomination commit `7a4646d11d198487acdcf8d3a97e36cb2bb6fe47`; it did not continue the final V5 manuscript revision.

The primary study contains four incident families and five admitted executions. Twelve comparison emitters, the source-traffic census, seven low-volume replay streams, and the Nomad attack-day burst are separate extensions. Repeated policy configurations and overlapping component views are not independent incident trials. Catalogue completeness is distinct from representativeness, token-feature readiness and closed attack inventories.

## Changes in this revision

- The catalogue census now covers all 28 Ethereum PoC files in the fixed March–September 2022 directories: four primary-study files and 24 extension files, corresponding to 23 windows across 22 emitters. Circle has two windows sharing 27 dates; duplicate XST source files use one window. Deduplicating emitter/date pairs gives 663 emitter-days, including 277 nonempty days: 130/277 (46.93%) fall below twenty selected transactions, and 386 dates are silent. The 51,452 emitter-specific transaction observations are not globally distinct chain transactions. The secondary multiplicity view has 690 window-days and 54,492 observations. `phase32/census_completion/` preserves the full file inventory, nominations, daily source counts and independent audit; the original sixteen-window result, 108/178, remains unchanged. All 22 creation dates are verified: excluding 214 strictly predeployment days gives 302/449 (67.26%) below twenty; excluding ten creation dates too gives 293/439 (66.74%).
- Nomad is described as an attack-day burst: 884 of 930 transactions occur on 1 August, and forty-six occur in the preceding twenty-nine days. The absence of positive Replica outflow is consistent with the documented Replica/BridgeRouter architecture.
- A post-scoring join with the protocol team's immutable public hash list identifies all twelve count candidates. Five are emitted under greedy B=5; seven are rejected by the hard cap. The first listed transaction is at 21:32:31 UTC, the first candidate at 22:43:32, the fifth notification at 23:17:33, and the first cap rejection at 23:23:01. Exhaustion therefore did not occur in the first minutes. List membership does not establish malicious intent, complete incident recall or precision.
- Saddle's first documented extraction is a strict observed sUSD maximum with descriptive rank 1/17. Since 1/17 exceeds 1/20, it is not a potential threshold crossing hidden solely by history ineligibility. The later 3/21 rank includes the first extraction and whitehat rescue among its preceding values.
- The Schnoodle result explicitly specifies unit burst capacity. Post-review sensitivity holds the refill rate and hard cap fixed: capacity five restores the reference even with initial credit one; a full initial capacity-five bucket reproduces the greedy sequence.
- The SEAL Saddle entry is present after Nomad on the full page. The manuscript now cites BlockSec's primary rescue account, which links the same transaction; SEAL remains corroborating evidence in the source audit.

## Reproduction and source boundaries

`phase31/verify_release.py` reproduces the V7 computational baseline. Phase32 adds the catalogue completion, protocol-list join and Saddle/bucket audit; the V8 release check binds these additions to the manuscript.

```bash
python papers/monitoring_jss/phase32/nomad_join/verify_join.py --check
python papers/monitoring_jss/phase32/saddle_bucket/audit.py --out /tmp/saddle_bucket_audit.json
```

The 125 Saddle/XCarnival/Audius transactions retain newly acquired full indexed response bytes and 2,103 events in `phase31/raw_payload_audit/raw_observations.zip`. Fresh offline extraction reproduces every V6.1 canonical normalized event-payload digest and frozen feature, and rejects three intentional integrity violations. This does not claim byte-identical recovery of the old unretained HTTP responses or equivalent payload retention for all earlier 667 Bacon/Rari and 400 first-wave transactions.

Nomad retains 930 complete normalized original-AWS bundles, transaction statuses and source receipts. Its 63 policy cells are independently reproducible. The original Parquet bodies are not distributed, so repeating byte-to-normalization extraction requires network source access. No source tier here authenticates Ethereum receipt roots or establishes a complete malicious-execution inventory.

## Author information and declarations

The existing eCampus and Karazin affiliations are retained and SMARTEST Research Center is added. PETs4DeFi support is acknowledged under Horizon Europe Grant Agreement No. 101308999, with the European Cybersecurity Competence Centre and the EU/ECCC disclaimer. The competing-interests statement discloses this reported financial support; no unsupported assertion about undisclosed interests is inferred.

AI-assisted research code development is disclosed briefly in Methods, separately from manuscript preparation in the final declaration, in accordance with the [current Elsevier AI policy](https://www.elsevier.com/about/policies-and-standards/generative-ai-policies-for-journals). The disclosed tools are OpenAI ChatGPT and Codex. Historical model snapshots were not systematically retained; the released analysis uses no language-model inference, and its calculations are reproduced from archived inputs. Funding and affiliation wording follow the author's instructions and verified project/institutional sources.

## Build and submission files

Use TeX Live with `elsarticle`, `lmodern`, `bibtex` and the packages listed in `main.tex`:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The official Elsevier class is pinned at `STM-Document-Engineering/elsarticle` commit `04aee43a9049051128c5d58b617dcd05e34df8b4`, supplied through `TEXINPUTS` and `BSTINPUTS`. This package does not redistribute a partial class installation.

The package includes exactly three figure assets, each cited in the text: `fig1_attack_time_selected.pdf`, `fig2_incident_relative_alerts.pdf`, and `fig3_external_readiness_census.pdf`. The unused V7 history figure is omitted. The article remains in 12-point preprint format; the release manifest records the verified page count. The five Highlights each satisfy the 85-character limit, and six keywords are supplied. No journal submission or Zenodo DOI is claimed.
