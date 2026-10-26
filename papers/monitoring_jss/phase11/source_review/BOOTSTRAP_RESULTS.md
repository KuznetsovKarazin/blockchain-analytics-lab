# Li.Fi constructor bootstrap

**The actual offline constructor/receipt check passed.** It reused already retained evidence after exact source compilation and made no network request or compiler invocation. A separate independent decoder also passed: it reconstructed nested ABI offsets using a different pinned Keccak implementation, without importing or rerunning the producer encoder.

| Item | Reconstructed value |
|---|---|
| Diamond | `0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1` |
| Constructor owner | `0xcb1e9fa11edd27098a6b2ff23cb6b79183ccf8ee` |
| Initial upgrade facet | `0xc46304a0b2accc4462d9bdcaa0f6bf632510d617` |
| Installed selector | `0x1f931c1c` (`diamondCut`) |
| Cut action | Add |
| Initializer | Zero address; empty calldata |

The 64-byte constructor suffix was decoded only after matching the full compiled creation prefix to factory initcode and checking the compiler ABI's two address parameters. The explorer's malformed constructor annotations were not used. Compiler metadata source hashes and the complete 4581-byte diamond runtime were checked without masking.

The successful deployment receipt contains exactly **two diamond-emitted events**, in order: `OwnershipTransferred` at block-level log index 122, followed by `DiamondCut` at index 123. There are no other-emitter events. The ownership event records a zero previous owner and the decoded constructor owner. The cut event's full **352-byte canonical ABI encoding** matches one Add action, the decoded facet address, one selector, zero initializer and empty initializer calldata. These block-level indices do not imply 122 or 123 events inside the deployment transaction.

The achieved tier is **compiler-bound constructor/receipt consistency**. This establishes a reproducible initial configuration from the constructor, not later continuity. The initial upgrade facet remains a candidate for its own runtime/source binding. Later ownership, selector activation, bridge configuration, arbitrary initializer effects and complete protocol population remain open. No incident payload, detector score or cohort admission is supplied by this check.

Owned decoded values are also provided in `bootstrap_results.json`; raw inputs and detailed acquisition/validation receipts are retained separately.
