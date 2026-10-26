# Phase 9: incident metadata screening

**All 13 entries retained: five ready for historical checks, two disclosure entries, four unresolved, and two prior development exclusions. No incident is admitted to scientific evaluation.**

The frame contains the existing catalogue entries dated from 19 March through 17 April 2022. This is a metadata screen of published reports, with no new detector scores. Full structured facts and evidence tiers are in [screening_results.json](screening_results.json).

Dates below are in 2022. The catalogue date is preserved even when the reported execution date differs. “Unresolved” denotes an evidence gap, not a negative example.

| Case | Catalogue date | Reported execution date | Chain evidence | Primary mechanism | Disposition |
|---|---|---|---|---|---|
| [Li.Fi](https://blog.li.fi/20th-march-the-exploit-e9e1c5c03eb9) | 03-20 | 03-20 UTC | Ethereum (report-link inference) | Untrusted external call | Historical checks next |
| [Umbrella Network](https://medium.com/umbrella-network/update-on-polar-stream-exploit-b2f4526327f2) | 03-20 | 03-20; timezone unspecified | Ethereum, BNB Smart Chain | Unresolved | Historical checks next |
| [OneRing Finance](https://medium.com/oneringfinance/onering-finance-exploit-post-mortem-after-oshare-hack-602a529db99b) | 03-21 | 03-21 UTC | Fantom | Price/oracle manipulation | Historical checks next |
| [CompoundTUSDSweepTokenBypass](https://www.openzeppelin.com/news/compound-tusd-integration-issue-retrospective) | 03-22 | Not established / inapplicable | Ethereum | Unresolved | Disclosure entry |
| [Auctus](https://medium.com/auctus/action-required-critical-vulnerability-3d448d4d0dcb) | 03-26 | Not established / inapplicable | Unresolved / inapplicable | Unresolved | Unresolved |
| [Revest Finance](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5) | 03-27 | 03-27 UTC | Ethereum | Reentrancy | Historical checks next |
| [Redacted Cartel](https://medium.com/immunefi/redacted-cartel-custom-approval-logic-bugfix-review-9b2d039ca2c5) | 03-29 | Not established / inapplicable | Unresolved / inapplicable | Authorization; vulnerability only | Disclosure entry |
| Ronin Network | 03-29 | Not established / inapplicable | Not re-adjudicated | Not re-adjudicated | Development excluded |
| [GYMNetwork](https://medium.com/@Beosin_com/beosin-analysis-of-the-attack-on-gymdefi-e5a23bfd93fe) | 04-09 | 04-10 stated; conflicts with catalogue; UTC unresolved | Unresolved / inapplicable | Migration accounting | Unresolved |
| Creat Future | 04-11 | Not established / inapplicable | Unresolved / inapplicable | Unresolved | Unresolved |
| [ElephantMoney](https://medium.com/elephant-money/reserve-exploit-52fd36ccc7e8) | 04-12 | Not established / inapplicable | BNB Smart Chain (report-link inference) | Price/oracle manipulation | Unresolved |
| [Rikkei Finance](https://rikkeifinance.medium.com/rikkei-finance-incident-investigation-report-b5b1745b0155) | 04-15 | 04-15 UTC | BNB Smart Chain (report-link inference) | Authorization | Historical checks next |
| BeanstalkFarms | 04-16 | 04-17; retained prior evidence | Not re-adjudicated | Not re-adjudicated | Development excluded |

“Historical checks next” means metadata readiness only. Deployment and upgrade history, the monitored population, routing continuity, full-window data and independently adjudicated execution labels still require evidence. Umbrella’s calendar date is not yet a verified UTC boundary. Revest’s separate historical-capability work does not change this screen’s admission count.

Compound–TUSD and Redacted are disclosure/remediation entries. Their disposition concerns those records; it does not assert that the protocols have never been attacked or provide negative-labelled monitoring examples.

GYM’s April 9/10 conflict remains unresolved, and its April migration event is separate from the June event. ElephantMoney’s April 12 publication date is not substituted for a verified execution day. Auctus’s warning and later chronology remain insufficiently reconciled; Creat Future lacks a matching accessible primary report.

Chain attribution through a report’s incident-specific Etherscan or BscScan link is explicitly marked as an inference. No chain receipt was fetched by this metadata screen. Chain names and protocol branding alone are insufficient.

Report text incidentally exposed transaction identifiers and short code fragments; their linked execution pages and exploit source files were not fetched. Revest reports were already known from earlier project work; no global blindness is claimed.

Mechanisms follow the earliest supported enabling violation: LI.FI’s external-call issue does not establish a bridge-authentication failure, and Rikkei’s unauthorized oracle replacement precedes its pricing effects. [CertiK’s Rikkei analysis](https://www.certik.com/blog/revisiting-rikkei-finance-exploit) corroborates that distinction; [BlockSec’s Revest analysis](https://blocksec.com/blog/revest-finance-vulnerabilities-more-than-re-entrancy) supports its report-based mechanism context.

The complete denominator, uncertain dates and unresolved mechanisms are retained. These results improve case selection and prevent disclosures from becoming attack positives; they do not establish detection quality, an independent multi-family evaluation or generalization.
