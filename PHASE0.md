# Phase 0 — Rust stack capability check

Testbed for CAWG identity assertion PR 269 (`cawg.vlei`), Rust only.
Run with `cargo test -p spike -- --nocapture`. Pinned: keriox `v0.19.0-rc.12`
(git, all crates from one tag), `acdc 0.2.0`, `said 2.0.0-rc.4`, `c2pa 0.92.2`.
GLEIF schemas in `infra/schemas/` (commit in `SOURCE_COMMIT`).

## Results

| # | Question | Test | Result |
|---|---|---|---|
| Q1 | AID signs arbitrary bytes; signature under sn 0 still verifies after rotation | `s1_sign_rotate` | **GO** |
| Q2 | 2-of-2 multisig AID; one signature rejected | `s2_group` | **GO** — `NotEnoughSigsError` |
| Q3 | Issue / revoke in a TEL anchored in the issuer KEL | `s3_registry` | **PARTIAL** — `teliox` writes ACDC **v2** registries (`rip`/`upd`) only. Resolved by `vlei-chain::tel` (below) |
| Q4a | Reproduce SAIDs of GLEIF's published vLEI schemas | `s4_acdc` | **GO** — all 6 match |
| Q4b | Hand-build an ACDC **v1** credential the legacy reader accepts | `s4_acdc` | **GO** |
| Q5 | c2pa-rs `signer_payload` encoding = RFC 8949 §4.2.1 deterministic | `s5_cbor` | **NO** — see finding F1 |
| Q6 | Custom `cawg.vlei` credential holder plugs into c2pa-rs | `s6_c2pa_holder` | **GO** — `CredentialHolder` / `SignatureVerifier` traits |
| Q7 | Delegation (GEDA → QVI) with an in-process witness | `s7_delegation` | **GO** |
| Q8 | Weighted `kt` thresholds | — | **NOT EXPOSED** — `keri-core` has `SignatureThreshold::Weighted`, but `keri-controller` only emits simple `u64` thresholds; needs `keri-core` event generation directly |

## Go / no-go

**KERI side: GO.** Signing, rotation, multisig, delegation and witnesses all
work in-process, without Docker.

**Credential side: GO (option 1 chosen).** Production vLEI credentials are
ACDC v1 (`ri`, `ACDC10JSON…`) with keripy's KERI 1.0 TEL (`vcp` / `iss` /
`rev`). `teliox` dropped that TEL (keriox commit `2703b426`), so the testbed
implements it in `crates/vlei-chain/src/tel.rs`. See the next section.

## Findings for PR 269 so far

- **F1 — Encoding conflict.** PR 269 requires `signer_payload` in core
  deterministic encoding (keys sorted: `role`, `sig_type`,
  `referenced_assertions`). c2pa-rs encodes it in struct order
  (`referenced_assertions`, `sig_type`, `role`), as the X.509 path does. A
  signer using c2pa-rs and a validator following the PR would disagree on the
  signed bytes. The PR must say which bytes are signed: the bytes as stored in
  the assertion, or a re-encoding.
- **F2 — ECR edges confirmed.** GLEIF's ECR schema allows either an `auth` edge
  or an `le` edge, matching the PR's QVI-issued vs LE-issued split.
- **F3 — ECR schema ID confirmed.** `EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw`
  quoted in the PR matches GLEIF's published schema.
- **F4 — Key state by `kel_seq_num` works.** Signatures stay verifiable against
  the establishment event they name after rotation, so the PR's `kel_seq_num`
  design is implementable (N4 can test the policy question, not the mechanics).

## Licence note

See "Licence and third-party material" in README.md.

## KERI 1.0 TEL (`vlei-chain::tel`)

Hand-built `vcp` / `iss` / `rev` for no-backer (`NB`) registries, anchored in
the issuer's KEL with `ixn` event seals `{i, s, d}`, plus a status check.
Run with `cargo test -p vlei-chain`.

| Test | What it shows | Result |
|---|---|---|
| `vectors::vcp_matches_reference_bytes` | `vcp` in the keripy serder format (`d` = `i`, nonce `n`) reproduced byte for byte | pass |
| `vectors::iss_matches_reference_bytes` | `iss` reproduced byte for byte | pass |
| `vectors::rev_matches_reference_bytes` | `rev` reproduced byte for byte | pass |
| `vectors::reference_events_parse_and_tampering_is_caught` | SAID checks reject edited events | pass |
| `anchoring::issue_then_revoke` | QVI anchors `vcp`, `iss`, `rev`; status goes Issued → Revoked; ACDC v1 credential carries the registry in `ri` | pass |
| `anchoring::unanchored_issuance_is_rejected` | `iss` not in the KEL → `NotAnchored` | pass |
| `anchoring::unanchored_revocation_is_rejected` | forged `rev` not in the KEL → `NotAnchored` | pass |
| `anchoring::revocation_must_chain_to_issuance` | `rev.p` ≠ `iss.d` → rejected | pass |
| `anchoring::registry_of_another_issuer_is_rejected` | registry `ii` ≠ credential issuer → rejected | pass |
| `anchoring::issuance_of_a_different_credential_is_rejected` | `iss.i` ≠ credential SAID → rejected | pass |

Limits, to keep in mind when reading results:

- **Vector provenance.** The reference events come from keriox's own KERI 1.0
  TEL tests (before `2703b426`), not from a keripy run we did ourselves. The
  `vcp` matches keripy's current serder layout, but a check against events
  exported from a real KERIA / vLEI deployment is still open.
- **Delivery is out of scope.** The status check takes the TEL events and the
  issuer's KEL as inputs. Fetching them from the issuer's witnesses (OOBI +
  TEL query) is not implemented; Phase 4 will feed them in from fixtures.
- **Simple issuance only.** `bis` / `brv` (backed registries) are not
  implemented; vLEI registries are no-backer.

## Next

Done: see PHASE1-2.md.
