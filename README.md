# TapeOut Upgrade Guard

Read-only X Layer mainnet evidence for TapeOut factory and beacon upgrades.

An independent AI-assisted developer prototype for ONE real human economic
owner. Not affiliated with TapeOut, OKX or NetLayerLabs. Requires neither
wallet connection nor signing, gas, staking, deposits, KYC or private keys.

**Static evidence dashboard:**
https://livastic-vm2-primary-20260911.github.io/tapeout-upgrade-guard/

**82-second silent, captioned demo video (under the three-minute limit):**
https://livastic-vm2-primary-20260911.github.io/tapeout-upgrade-guard/demo.mp4

The video is a screen-and-evidence walkthrough, not a third-party testimonial
or a claim of continuous live monitoring, paid orders or contest acceptance.

## What it checks

At a pinned X Layer block (chain ID 196), the CLI reads the EIP-1967
implementation storage pointer of the TapeOut factory proxy and the
implementation() method of the Transistor and Circuit beacons.

For the three configured components, the tool preserves the actual deployed
runtime bytes' SHA-256 digests and byte lengths, code addresses,
owner() observations when readable, block number/hash and timestamp.

The public third-party reference linked below currently documents the
factory proxy 0x1f09daefa827f02cbb40967cc91b259763760761 and
implementation 0x74956236ab64ed143933040b4137e8a352e4d17b.

**But the live factory EIP-1967 implementation slot on X Layer blocks
73,981,688 and 73,981,911 returned
0xb41c1e7602eb5734be2430b72178ccb814a5293d.**

This is a verifiable *documentation-reference-versus-pinned-onchain*
difference, NOT proof of a malicious upgrade or security vulnerability.
The third-party reference may simply be stale; the deployment publisher
and upgrade history need independent verification.

## Reproduce

Python 3.10+ standard library only; no wallet, credentials or installation.

    python3 -B tapeout_guard.py snapshot --out evidence/now.json
    python3 -B tapeout_guard.py snapshot --block 73981688 --out evidence/old.json
    python3 -B tapeout_guard.py diff evidence/old.json evidence/now.json

Source snapshots saved in this repository:

- evidence/20261023_xlayer_block_73981688.json: block 73,981,688,
  hash 0xf6e3991f463bfa226a5ec5673a4d8fa2547a1b1da3bf670a2ea916499eb41ebf.
- evidence/20261023_xlayer_mainnet_pinned.json: block 73,981,911,
  hash 0x3fc1c32eff2b4b91347c3f37e06876116eedb5ca509b3cdc5aba71909fed6bea.
- evidence/comparison_73981688_to_73981911.json:
  NO_OBSERVED_DIFFERENCE in pointer/code/owner read fields across these two
  blocks. Does NOT rule out intermediate changes.

Run offline tests:

    python3 -B -m unittest discover -s tests -v
    node --check docs/app.js

**29/29 tests passed** October 23, 2026. Two genuine read-only X Layer
pinned-block snapshots succeeded. No reported customer sale or cash earned.

## Security and data collection model

The only permitted RPC calls are eth_chainId, eth_blockNumber,
eth_getBlockByNumber, eth_getCode, eth_getStorageAt and eth_call.
The tool has no transaction method; no writes to the chain, approvals,
signatures, transfers or RPC private keys. It aborts if critical code
or implementation evidence is missing, the wrong chain is returned,
or a referenced implementation has no runtime bytecode.

The comparison checks implementation addresses, runtime SHA-256 fingerprints
(not Ethereum Keccak-256 hashes), code lengths and optional owner() readings.
An owner() result is not complete effective upgrade authority.
An EIP-1967 admin slot of zero is not proof there is no other admin.
No check proves contract source code authenticity, upgrade history
completeness, protocol security, treasury backing, wallet security,
permission safety or financial return. One public RPC is not a consensus proof.

The browser dashboard uses a checked-in static JSON snapshot and
performs optional two-file local comparisons. No wallet connection,
server upload or surveillance. The demonstration is not continuously live.

## Business potential (hypothesis, not revenue)

Potential genuine buyers: TapeOut application integrators, developer tooling
vendors, community safety maintainers and risk teams monitoring upgradeable
X Layer contracts. Proposed optional fixed-fee human-reviewed bundle:
two time-pinned snapshots, a narrow source-document reconciliation,
one-source-verified deployment table and a written actionable change summary.

A plausible initial seller ASK is 9-19 native USDC for a mutually agreed
small scope, strictly conditional on the actual independent buyer agreeing
to legal terms and correctly paying the existing original VM1 MetaMask
recipient. This is NOT a buyer-accepted price, contract, forecast,
earnings claim, or delivered service. Zero paying customers are claimed.
No guarantee the competition will award this tool any prize.

## Independent sources

- Official 2026 TapeOut Accelerate event and its eligibility terms:
  https://web3.okx.com/ko/xlayer/build-x-series
- Third-party deployed TapeOut contract reference, checked Oct 23:
  https://github.com/NetLayerLabs/Cerebr/blob/main/TAPEOUT.md
- EIP-1967 standard:
  https://eips.ethereum.org/EIPS/eip-1967
- X Layer public explorer:
  https://www.oklink.com/xlayer
- Public chain RPC:
  https://rpc.xlayer.tech

This independent on-chain factory/beacon integrity product was developed in
the October 2026 event window and is not the same as the previously
submitted CPU0 per-circuit report under a separate PayAPI Market account.


### Buyer-initiated paid review (not yet sold)

The public dashboard includes an **optional request-for-quote** contact for
independent buyers. Indicative seller asks are 9 USDC for a narrow public
deployment drift check, and 19 USDC for one expanded, human-reviewed
release evidence report. These are *not* approved budgets, orders,
invoices or income. No buyer has purchased the service. Payment method,
scope, AI disclosure, timeline, human owner review and legal terms must
be agreed separately before any paid deliverable. Free verification
remains available without payment, self-trades or wallet connection.
