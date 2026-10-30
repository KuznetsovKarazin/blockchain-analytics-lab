# Catalogue-complete extension census

The frozen V7 release remains unchanged. This Phase32 extension resolves every
previously unaccounted Ethereum-mainnet source file in the pinned March–September
2022 DeFiHackLabs directory frame. It does not claim coverage beyond that frame,
or a random sample of incidents, nor automatic admission of successful attacks.

`CATALOGUE_COVERAGE.json` accounts for all 67 source files: 39 other-chain files,
four primary-study files, and 24 extension files. The extension files map to 23
unique core/fork windows over 22 unique operational components. Exact XST
duplicates collapse. Both Circle forks remain and their 27 overlapping UTC dates
are counted once in the primary emitter-day aggregate. Thus 690 nominal
window-days correspond to **663 unique emitter-days**.

The new `CANDIDATE_FRAME.json`, `FORK_WINDOWS.json` and `ACQUISITION_FREEZE.json`
were frozen before new traffic measurement and published before CI acquisition.
`freeze_frame.py` documents their construction and refuses to overwrite an
existing freeze. The complete source mapping records ambiguous or alternative
component roles instead of changing cores after observing traffic.

## Reproduce the offline audit

From the repository root, using Python 3.11 or later and its standard library:

```bash
python papers/monitoring_jss/phase32/census_completion/metadata/acquire_and_verify.py
python papers/monitoring_jss/phase32/census_completion/verify_census.py --out /tmp/phase32-census-audit
python papers/monitoring_jss/phase32/census_completion/test_integrity.py --out /tmp/phase32-integrity-tests.json
```

`verify_census.py` imports neither the source collector nor the original census
implementation. It independently recounts all preserved selected transaction
coordinates, checks daily and case arithmetic, complete listed source/row-group
coverage and HTTP range bindings, reconciles all source-file dispositions,
checks overlapping Circle days, and calculates deduplicated activity and
creation-date sensitivities. Original sixteen-case aggregates are retained as a
separate baseline and checked against their unchanged files.

The integrity tests use disposable copies to ensure changed coordinates, a
missing projected row group, and an omitted case-day are rejected. They also
check that the retained evidence is unchanged. The successful acquisition ran
from source commit `8d72d1d9e5e507ecb2a2b95adeda1b85958ef5b2` in GitHub Actions
run `41026432427`; all four batches completed.

The primary result is **130 of 277 nonempty unique emitter-days (46.9%)** below
20 selected transactions, with 386 zero days out of 663 unique emitter-days.
The original sixteen-case result remains separately available: 108 of 178
nonempty days (60.7%). `audit/CENSUS_AUDIT.json` includes both aggregates,
nominal window-weighted totals, and creation-date sensitivities for all 22
emitters.

The figure is reproduced with `python
papers/monitoring_jss/phase32/census_completion/plot_census.py` (Matplotlib
required). Its companion JSON binds exact input hashes and the PDF hash, and
records every plotted count. Circle's 33-day union is labelled explicitly.

Source collection additionally requires `pyarrow==19.0.1` and network access.
The four bounded CI batches preserve all complete and incomplete evidence in
artifacts; a successful four-batch collection is additionally preserved on a
separate results branch before independent audit. `source_census.py --batch N
--output NEW_DIRECTORY` implements this acquisition. Do not reuse or overwrite
an old attempt directory. Resource caps, exact projected columns, and the
whole-UTC-day anchor rule are specified in `PROTOCOL.md`.

## Evidence and limits

- `metadata/`: SHA-bound original indexed fork-block and contract-creation
  responses, covering all seven new windows and six new addresses.
- `results/batch_*/`: complete census records, raw XML source inventories,
  HTTP range receipts, source-coverage manifests and compressed selected
  transaction-coordinate sets.
- `audit/`: independently regenerated summary and daily tables when verification
  has completed.

The new acquisition scans every original row group for three columns. Sparse
Parquet bodies are temporary and not distributed. Offline recounting begins
with saved selected coordinates; repeating the original byte-to-selection
extraction requires source access. Source identity and range hashes do not
constitute receipt-root authentication. The original sixteen-case census has
its documented aggregate/source-receipt evidence tier; the additional coordinate
retention is not retroactively attributed to it.

Address-creation metadata supports sensitivity analyses, not proof of every
historical code incarnation. Missing measurements are never imputed as zero.
No detector score, new attack label, exploit hit, or population performance
estimate is produced by this census.
