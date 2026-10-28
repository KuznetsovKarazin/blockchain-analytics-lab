# Public sealed-evidence capsule

This capsule permits offline verification of the reported Phase16 results from
the retained observations, decisions and independently adjudicated references.
It contains 2,147 byte-exact files in a 4.71 MB ZIP. Its separate manifest pins
every included file and 32 repository dependencies by SHA-256.

The verifier runs the unchanged `exact_reference_join.py` against the sealed
inputs. It validates both complete observation/decision windows and reconstructs
the 54 method–policy–budget aggregates and 27 across-case comparisons. It also
compares every reference-funnel and candidate-adjudication row with the archived
join. This is validation and aggregation of existing decisions, not another
detector experiment: no source acquisition, detector scoring, parameter fitting,
label change or raw blockchain audit is performed.

From the repository root, using Python and its standard library (tested with Python 3.12.14):

```sh
python papers/monitoring_jss/phase16/public_evidence/verify_public_evidence.py \
  --expected-manifest-sha256 792b2c2abf3f7ccc4274455900c13c02ad2d040355120e7971ec65ebcf491f8a \
  --output /tmp/article2-phase16-public-check
```

Use a fresh output directory outside the repository. The verifier leaves the
repository unchanged and writes extracted evidence, a newly aggregated join and
`verification_report.json` beneath that output. It does not require the original
workspace directories, network access, PyArrow or the multi-gigabyte raw-source
archives. The published manifest and checksums should be obtained from the same
reviewed Git commit as the verifier and capsule.

All original JSON and compressed decision bytes remain unchanged. The only
adapter replaces `exact_reference_join.binding` temporarily: explicitly listed
historical absolute paths map to current verified files, then the original
binding function checks the original SHA-256. Unlisted absolute paths are
rejected. Relative input/gate path validation remains the original driver code;
no scientific validator or scoring function is replaced. The adapter is restored
after the join. Historical absolute paths are identifiers, never write targets.

The actual publication check reproduced all aggregate fields except the newly
generated `created_utc` timestamp. The 81 reference-funnel rows and five candidate
dispositions, including their compressed bytes, matched the archived outputs.
`verification_report.json` records the exercised code and artifact hashes.
`test_report.json` records targeted failure checks for a wrong container hash,
wrong member hash, extra member, path traversal and binding outside the verified
file set. No historical source audit is promoted to a newly repeated audit.

The capsule includes selected observation streams, their selection/source-audit
manifests, every sealed replay artifact, the final reference inventory and
reviews, factual primary-source evidence, exact reference source-fact audits,
the original joined results and interpretation checks. Relevant transport and
recovery receipts are retained as historical evidence. Published repository
code and gate documents are referenced rather than duplicated in the ZIP.

Raw accepted A1/A2 response bodies and the 18 original whole-source objects are
not in this capsule. Repeating the full archive selection/feature audit requires
those retained raw archives or a separately documented source acquisition.
Historical PASS receipts and hashes alone do not prove source completeness or
primary-report truth. Full copyrighted primary-report retrieval text is also
excluded; factual extracts, public source URLs, locations and retrieval hashes
remain available. Both reference inventories remain known subsets, and the
original inference limits in the [results](../manuscript/EXTERNAL_CASE_RESULTS.md)
continue to apply.

`build_public_evidence.py` is the maintainer's selection/packaging utility for
the separately recovered metadata tree. It copies exact bytes and does not run
detectors. Normal reviewers need only the verification command above.
