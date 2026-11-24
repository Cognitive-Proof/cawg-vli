# Phases 1–2 — trust chain and credentials

Run with `cargo test -p vlei-chain`. Generate fixtures with
`cargo run -p testbed-cli -- chain --out fixtures/generated`.

## What gets built (`crates/vlei-chain/src/chain.rs`)

```text
GLEIF Root (2-of-3 multisig group)
  └─ GEDA (delegated from Root)                        registry ── QVI credential → QVI
       └─ QVI "Northwind" (delegated from GEDA)         registry ── LE credential → Fabrikam
            │                                                       OOR (Alice, CFO)
            │                                                       ECR (Bob, Press Officer)
            └─ Fabrikam (2-of-2 multisig group)         registry ── OOR auth → QVI (for Alice)
                                                                    ECR auth → QVI (for Bob)
                                                                    ECR → Carol (Editor, edge to LE)
Alice, Bob, Carol: single-key AIDs
```

- Organisation AIDs are KERI group identifiers held by member AIDs. Every
  organisation event (delegating seals, registry and issuance seals) is an
  `ixn` signed by the group's threshold of members.
- Credentials are ACDC 1.0 in keripy's layout (`crates/vlei-chain/src/credential.rs`),
  with nested `a` / `e` / `r` SAIDs and rule text taken from GLEIF's schemas.
  Each one is checked against its GLEIF JSON schema and by the `acdc` crate's
  v1 reader when issued. ECR credentials are private (`u` salts).
- Every credential has a KERI 1.0 TEL (`vcp` + `iss`) anchored in its
  issuer's KEL (`crates/vlei-chain/src/tel.rs`).

## Tests

| Test | Shows |
|---|---|
| `chain::full_chain_builds_and_links` | Root has 3 keys; GEDA's delegator is Root; QVI's is GEDA; Fabrikam has 2 keys; all 7 credentials issued; edges and issuer/issuee links match the vLEI EGF (incl. `I2I` on OOR / ECR via QVI); all 14 KELs replay into a fresh verifier database |
| `chain::revocation_flips_status` | revoking Alice's OOR makes it Revoked and leaves Bob's ECR Issued |
| `chain::delegated_kel_alone_does_not_verify` | GEDA's KEL is rejected without GLEIF Root's, and accepted once Root's is added |
| `chain::missing_required_claim_fails_schema` | the schema check rejects a malformed OOR |
| `chain::embedded_schema_saids_reproduce` | embedded schemas still hash to their `$id` |
| `anchoring::*`, `vectors::*` | TEL behaviour (see PHASE0.md) |

## Fixtures (`fixtures/generated/`, not committed; AIDs change on each run)

`fixtures.json` holds everything; the same data is split into
`credentials/`, `tel/`, `registries/` and `kels/`. No private keys are
written. The signing phase rebuilds the world in-process to get keys.

Sizes from one run: credentials 1.3–2.1 KB each (ECR largest, because of the
privacy disclaimer and salts); KELs 5.9 KB for the trust chain's groups,
11.7 KB for all 14 AIDs.

## Limits

- **No witnesses yet.** All parties share one controller database, so KELs
  carry no witness receipts and there are no OOBIs to resolve. Phase 3 needs
  OOBIs for `signer_aid_oobi`; witnesses come in then.
- **CESR 2.0 attachments.** keriox writes KEL attachments in CESR 2.0
  (`-_AAACAA…`). vLEI production (keripy 1.x / KERIA) uses CESR 1.0. Events
  are KERI 1.0 either way.
- **Field order not cross-checked.** Credential and TEL layouts follow keripy
  conventions, but no credential was compared byte for byte with one from a
  real vLEI issuance.
- **Weighted thresholds** are still not covered (Phase 0, Q8).

## Findings for PR 269 from this phase

- **F5 — The payload can't be verified from what it carries.** PR 269's
  map carries the signer's OOBIs only. Verifying the chain also needs the KELs
  of the QVI (for `qvi_cred`, `le_cred`, OOR / QVI-issued ECR), of the legal
  entity (for the OOR / ECR auth credentials and LE-issued ECRs), of GEDA and
  GLEIF Root (delegation), and a TEL for every credential. None of those have
  a source in the payload; the PR's "assumed setup" NOTE covers only the QVI
  credential. The test that replays the chain needed 14 KELs and 7 TELs.
- **F6 — Embedding an ECR conflicts with its own rules.** The ECR schema's
  `privacyDisclaimer` says holders must present it "in a privacy-preserving
  manner" using IPEX. PR 269 puts the full ECR JSON (salts included) into a
  C2PA manifest that anyone can read. The PR should address this or limit
  `cawg.vlei` to OOR credentials.
- **F7 — Size.** A full OOR bundle (`qvi_cred` + `le_cred` + auth + OOR) is
  about 6 KB of JSON; an ECR bundle via a QVI about 7 KB, before signatures and
  OOBIs. That's fine for `reserve_size`, but worth stating, since the
  credentials are repeated in every signed asset.
- **F8 — "Auth" credentials go to the QVI.** OOR and ECR authorisation
  credentials are issued by the legal entity *to the QVI* (the schema's `I2I`
  edge relies on that). PR 269's wording ("the `auth_cred` field … MUST
  contain JSON encoded OOR Authorization Credential") is consistent with this,
  but its validation step should say to check that the auth credential's
  issuee is the role credential's issuer.
