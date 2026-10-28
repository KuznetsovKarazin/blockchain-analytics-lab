# Actual Phase16 resource recovery

Attempt A1 ended with externally observed ENOSPC after preparing 19 days. Its original checkpoint remains `OPEN_REQUEST_PENDING`: 729 authenticated successful ranges total 5,145,712,739 bytes; request 730 has unknown actual received bytes. No detector replay or new incident-reference acquisition had started. The forensic archive preserves the original files and failed empty checkpoint; `../delivery/a1_durable_preservation.json` links its saved catalog.

The root accepted the separate prospective storage amendment at 2026-10-28T12:01:21.684405Z, after an external closure seal and explicit review of prior source-only exposure. It conservatively charges the entire 275,821-byte unresolved request, authorizes one exact reacquisition, and preserves cumulative GET/byte caps. The absolute operational deadline is A1 start plus 14,400 seconds. Compact immutable response blobs replace sparse cache copies. Both original case windows, source identities, scientific rules, measurement acceptances and detector code remain unchanged.

The files under `actual/` contain this accepted chain. Code and synthetic reports are preparation evidence, not source admission or scientific performance. A2 must complete independent transport and source audits before assembly and one frozen replay per case. New reference acquisition follows a seal of both completed decision stages. `REPLAY_AND_REFERENCES.md` specifies that workflow.

The earlier `../continuation/` wall-limit candidate was never activated and cannot justify ENOSPC recovery. Its explicitly pinned pure helpers are reused without invoking its authorization or acquisition route.
