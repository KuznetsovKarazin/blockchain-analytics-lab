# Coverage bounds for the fixed-address experiment

These are consequences of the frozen observation and decision rules, not claims of a new detection algorithm or measured incident performance. They clarify what the external-case experiment can establish.

Let \(P_d\) be the independently verified reference execution transactions on UTC day \(d\), \(S_d\) the transactions selected by at least one log emitted by a frozen core address, and \(N_{m,d}\) the transactions that receive an emitted notification from method \(m\) at daily cap \(B\). The replay never inserts a labeled but unselected transaction into its input. Therefore

\[
N_{m,d}\subseteq S_d,\qquad |N_{m,d}|\le B.
\]

For the semantic method, define \(E_d\subseteq S_d\) as transactions with at least one positive token-separated core-sender external outflow and at least 19 strictly earlier positive observations for that token within the current UTC day. The frozen minimum-history rule gives

\[
N_{\mathrm{semantic},d}\subseteq E_d\subseteq S_d.
\]

For a nonempty reference set \(P=\bigcup_d P_d\), fully observed transaction notification coverage consequently satisfies

\[
\frac{\sum_d|P_d\cap N_{m,d}|}{|P|}
\le \frac{\sum_d\min\{B,|P_d\cap S_d|\}}{|P|}.
\]

For the semantic method, replace \(S_d\) by \(E_d\) for a possibly tighter bound. The proof is set inclusion plus the daily hard cap; it makes no probabilistic assumptions. Grouping and budget allocation can lower realized coverage further. These bounds concern notified execution transactions, not a guarantee about incident-level attribution or prevention.

The first 19 positive observations of a token after each daily reset cannot make that token eligible. This does not mean the first 19 transactions of every day are cold: a transaction may contain multiple tokens, and zeros or absent outflows do not enter the conditional magnitude history. At history size 19, the smallest rank fraction is 1/20; equality handling remains the frozen implementation's rule.

The outer reference denominator must remain visible. Unselected executions, absent core outflows and cold start must not disappear through a conditional denominator. If the positive inventory is incomplete, the rate describes the verified known subset only. If observation evidence is missing, do not insert a zero, an empty day or a measured miss into these formulas.

The planned scientific test is whether the semantic rule improves verified-execution notification coverage over the count rule at the same offered daily budget, and at what realized notification load. A tie or a reversal is informative when source coverage, initialization, labels and outcome-independent selection are disclosed. Unknown notifications are not false positives. The LiFi event reconstruction is supporting evidence about historical observability; it does not by itself establish the main monitoring contribution.
