# Revest deployment provenance evidence

The deployment review links 24 captured Blockscout V2 responses by URL, SHA-256
and byte count. Five creation transactions and the registry initialization
establish the reported creation and initial binding facts within this explorer's
records. They do not establish continuous routing during the proposed 2022
window. The independent review retains that distinction.

The private phase 7 evidence package preserves the exact responses, three fetch
manifests and the historical fetch/build scripts. The initial fetch script
produced 15 responses; nine subsequent block/history/initialization responses
are documented by the two additional manifests. It is not a single portable
script that reproduces every request. Public URLs remain retrieval instructions,
not a guarantee that a future response will match the captured bytes.

The historical scripts contain absolute workspace paths and the build script
writes its output. For offline inspection, extract the package into a new
directory, map the original workspace prefix to that directory, and direct any
generated output to a separate working directory. Verify the retained member
hashes before parsing. Do not overwrite the original evidence. No external
request is needed to inspect the retained records.

Verified-source JSON responses retain their original embedded notices. Main
Revest sources carry GPL notices, while additional sources include MIT and
UNLICENSED interfaces. The included RevestContracts GPL-3.0 LICENSE matches
Git blob `f288702d2fa16d3cdf0035b15a9fcbc552cd88e7` at source commit
`f4b5a5a898d202a5040f72ec7b1196de5f05e5f8`; it is not a blanket licence for all
response content. Raw responses remain private and are not in this Git tree.
The full phase 6 exploit proof of concept is absent from both Git and this
phase 7 package.

The exact-address web search initially exposed an already-known incident
transaction snippet and a third-party exploit-code snippet. Neither destination
was opened or used in feature design, and no exploit code was executed. This
limited exposure is retained in the deployment review; no global blindness or
independent holdout admission is claimed.
