# Catalogue-completion source census (Phase32)

This post-review extension accounts for every Ethereum-mainnet PoC source file
in `src/test/2022-03` through `2022-09` at DeFiHackLabs commit
`0a9b9fd81c50767ff49f81089fbf8934f2f45b02`. The complete ledger has 67 files:
39 other-chain exclusions, four files represented in the primary study,
16 original extension files and eight newly measured source files. It does not
retroactively redefine the historical sixteen-case convenience selection.

The eight additions identify six nominated operational components and seven
unique core/fork windows. The two Circle files share a core but use different
forks, so both windows remain. The two XST files share both core and fork and are
measured once. The revised extension therefore comprises **23 windows over
22 unique nominated emitters**, accounting for all 24 nonprimary Ethereum files.
Nomination follows the explicit source-designated vulnerable component or the
named directly targeted operational contract; alternative component roles are
recorded in `metadata/SOURCE_MAPPING.json`. Nominations are investigator
interpretations, fixed before traffic. No address is replaced because it is
silent. A complete source-file frame is not an exhaustive sample of Ethereum
incidents or all contracts involved in each mechanism.

Windows preserve the Phase28 rule: 30 whole UTC dates ending on the indexed PoC
fork-block date. Redacted's date is in December 2021 despite its source-directory
name. No anchor is shifted to an incident date. Source statuses are descriptive
and no reproduction is automatically admitted as a historical attack.

The primary descriptive aggregate deduplicates `(core_address, UTC date)` across
the 23 windows. The two Circle windows overlap for 27 days: the nominal 690
window-days comprise **663 unique emitter-days**, including 183 new emitter-days.
The original 480-day, sixteen-emitter cohort and the nominal window-weighted
aggregate are retained separately. Silent and nonempty days, and indexed
creation-date sensitivity, are distinct denominators. No missing day is zero.

## Frozen acquisition

The four batches in `CANDIDATE_FRAME.json` read the same three original AWS
Ethereum Parquet columns as Phase28: address, block number and transaction index.
Every row group must be covered. Within a batch, each source day is acquired
once and all applicable fixed cores are counted from that projection. Complete
source inventories, exact HTTP206/If-Match ranges, response SHA256, row-group
coverage manifests and sorted distinct transaction coordinates are retained.
Temporary sparse Parquet source bodies are not distributed. Offline recounting
begins with preserved selected coordinates and coverage receipts; reproducing
byte-to-selection requires online source access, and receipt roots are not
independently authenticated.

Each batch retains the original limits: 1,000 range GETs, 1.4GB actual range
response bytes and 1,000 seconds of acquisition time, with no retries or
redirects. Listings are separately recorded and limited to one 300,000-byte
response per source day. No scores or attack labels are used. Failed or partial
batches remain incomplete; any continuation requires a separate recorded
attempt and must retain the original failure rather than overwriting it.

After acquisition, a separate standard-library verifier checks all seven cases,
210 nominal new window-days, selected-coordinate hashes/counts, metadata,
complete source row/group coverage, HTTP range identities and accounting,
all28-file coverage, duplicated Circle-day equality, aggregate denominators and
deployment-conditioned sensitivity. Configuration or source-file coverage is not
population detection performance.
