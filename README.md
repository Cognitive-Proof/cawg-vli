# cawg-vlei

Rust testbed for the CAWG identity assertion `cawg.vlei` credential type
(decentralized-identity/cawg-identity-assertion PR 269): build a local vLEI
trust chain, sign identity assertions with KERI keys, and validate them by
following the PR's validation steps literally.

Status: Phases 0–5 done — see [PHASE0.md](PHASE0.md) (capability check, KERI 1.0 TEL),
[PHASE1-2.md](PHASE1-2.md) (trust chain, credentials, fixtures), [PHASE3.md](PHASE3.md)
(signing, signed C2PA assets), [PHASE4.md](PHASE4.md) (validator) and [PHASE5.md](PHASE5.md) (negative
tests). Next: Phase 6, the findings write-up for PR 269.

```bash
cargo test --workspace
cargo run -p testbed-cli -- chain --out fixtures/generated
cargo run -p testbed-cli -- sign --out fixtures/generated
cargo run -p testbed-cli -- verify --out fixtures/generated
```

```
crates/spike        Phase 0 capability tests
crates/vlei-chain   AIDs, delegation, credential issuance (Phase 1–2)
crates/vlei-sign    signer_payload encoding and KERI signing (Phase 3)
crates/vlei-holder  c2pa-rs credential holder (Phase 3)
crates/vlei-verify  validator for PR 269 (Phase 4)
crates/testbed-cli  CLI
infra/schemas       GLEIF vLEI credential schemas (ACDC v1)
infra/cddl          corrected CDDL for vlei-signature-payload-map
```

## Licence and third-party material

No licence has been chosen for this repository yet. Until one is added, the
code here is not licensed for reuse.

Third-party material included or adapted:

| What | Where | Source | Licence |
|---|---|---|---|
| vLEI credential schemas | `infra/schemas/*.json` | [GLEIF-IT/vLEI-schema](https://github.com/GLEIF-IT/vLEI-schema) at the commit in `infra/schemas/SOURCE_COMMIT` | Apache-2.0 |
| KERI 1.0 TEL reference events (`vcp`, `iss`, `rev`) | `crates/vlei-chain/tests/vectors.rs` | [THCLab/keriox](https://github.com/THCLab/keriox) tests, commit `2703b426^` | EUPL-1.2 |
| Delegation and group flow in the Phase 0 spikes | `crates/spike/tests/s2_group.rs`, `s7_delegation.rs` | adapted from keriox's `keri-controller` tests | EUPL-1.2 |

Dependencies keep their own licences; keriox's crates (`keri-core`,
`keri-controller`, `teliox`) and `acdc`, `said`, `cesrox` are EUPL-1.2.
