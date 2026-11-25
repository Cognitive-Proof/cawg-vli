# Phase 3 — signing

Run with `cargo test -p vlei-sign -p vlei-holder`. Generate signed assets
with `cargo run -p testbed-cli -- sign --out fixtures/generated`.

## What changed in the chain

- **Witness and OOBIs.** An in-process keriox witness (`witness1:3232`, reached
  through `TestTransport`, nothing on the network) serves every signer's KEL.
  Signers get keripy-style OOBIs, `http://witness1:3232/oobi/{aid}/witness/{wid}`,
  and `vlei_chain::oobi::resolve` turns one into a KEL in a fresh verifier.
- **Dana**, a person who signs with three devices (2-of-3 group AID, witnessed),
  holds an OOR (Chief Executive Officer), to exercise multi-signature `aid_sig`.
- **Fabrikam** is now witnessed, so the legal entity can sign for itself.
- keriox's witness does not combine members' partly signed copies of a group
  event, so the testbed sends one fully signed copy and then pulls the
  receipted KEL back through the group's OOBI (`World::publish_org`).

## Signing (`crates/vlei-sign`)

- `encode_signer_payload` gives the bytes to sign. `Encoding::Deterministic`
  follows PR 269 (RFC 8949 §4.2.1); `Encoding::C2paRs` is what c2pa-rs stores.
- `sign` builds the `vlei-signature-payload-map`: each signing key signs, and
  the index in each CESR indexed signature is the key's position in `k` at
  `kel_seq_num`. With `Options { anchor: true }`, the signer first anchors a
  digest seal `{d: Blake3-256(payload)}` in an `ixn` and sets `anchor_seq_num`.
- `VleiSignaturePayload::to_cbor` writes core deterministic CBOR.
- `infra/cddl/vlei-signature-payload.cddl` is the PR's map with its CDDL fixed.

## In C2PA assets (`crates/vlei-holder`)

- `VleiCredentialHolder` implements c2pa-rs's `CredentialHolder` for
  `sig_type` `cawg.vlei`. c2pa-rs builds `signer_payload` (hashes of
  `c2pa.actions.v2` and `c2pa.hash.data`, role `cawg.creator`) and stores our
  map in the identity assertion's `signature`.
- The C2PA claim itself is signed with a throwaway ES256 certificate generated
  per run with `rcgen` (test CA + end-entity with digitalSignature, emailProtection
  EKU and an Authority Key Identifier, as c2pa-rs's profile check requires).

## Cases (`testbed sign`)

| Case | Signer | `role_cred` | `aid_sig` | Map size |
|---|---|---|---|---|
| `oor` | Alice | OOR auth + OOR | 1 | 6.3 KB |
| `ecr-qvi` | Bob | ECR auth + ECR (QVI-issued) | 1 | 7.3 KB |
| `ecr-le` | Carol | `""` + ECR (LE-issued) | 1 | 5.2 KB |
| `no-role` | Fabrikam (2-of-2) | none | 2 | 3.2 KB |
| `anchored` | Alice, `anchor_seq_num` set | OOR auth + OOR | 1 | 6.3 KB |
| `multisig` | Dana (2-of-3) | OOR auth + OOR | 2 | 6.4 KB |

Each case writes the PNG, the map (`maps/CASE.cbor`) and the whole identity
assertion in diagnostic notation (`diag/CASE.cbordiag`, with `signature` shown
as embedded CBOR `<< … >>`). All six maps validate against the corrected CDDL
with the `cddl` tool (`cddl validate --cddl infra/cddl/vlei-signature-payload.cddl --cbor …`).

## Tests

| Test | Shows |
|---|---|
| `vlei-sign` `each_signer_produces_a_verifiable_map` | all five signers' maps verify with keriox at `kel_seq_num`; deterministic CBOR round-trips; Carol's `auth_cred` is `""` |
| `vlei-sign` `one_of_two_group_signatures_fails_threshold` | dropping one of Dana's two signatures fails verification |
| `vlei-sign` `anchored_signature_records_payload_digest` | the event at `anchor_seq_num` carries the digest seal, for a person and a group |
| `vlei-sign` `signed_bytes_depend_on_encoding_choice` | F1 (below) |
| `vlei-holder` `signed_assets_carry_verifiable_vlei_signatures` | six PNGs validate as C2PA; their `aid_sig` verifies over the deterministic re-encoding of the stored `signer_payload`, and *not* over the stored bytes |
| `vlei-chain` `signer_oobi_resolves_to_kel_in_fresh_verifier` | Alice's and Dana's OOBIs resolve to KELs in a fresh verifier; a wrong witness host fails |

## Findings for PR 269 from this phase

- **F1, confirmed in real assets.** c2pa-rs stores `signer_payload` in its own
  key order (`referenced_assertions`, `sig_type`, `role`; inside each
  reference `url`, `hash`). Signing the core deterministic bytes, as PR 269
  requires, means a validator must decode and re-encode before checking
  `aid_sig`; checking the bytes as stored fails. Either rule works, but the PR
  has to pick one and say so, and it differs from the X.509 path, which signs
  the bytes as stored.
- **F9 — anchoring wording.** PR 269 says the payload hash must be "one of the
  values in the array of the `a` field". KERI's `a` holds seals (maps), not bare
  digests. The testbed anchors a digest seal `{"d": "<Blake3-256 digest>"}`; the
  PR should say that, and name the digest algorithm (the testbed uses
  Blake3-256, CESR code `E`).
- **F10 — the PR's CDDL does not parse.** `cddl compile-cddl` rejects the map
  as written in the PR at `?"role_cred" = (…)`. The corrected definition is in
  `infra/cddl/vlei-signature-payload.cddl`.
- **F11 — size guidance.** c2pa-rs reserves space for the `signature` field
  before signing. Measured maps are 3.2–7.3 KB; the testbed reserves 16 KB.
  The PR should give implementers a bound, since the size depends on which
  credentials are embedded.
- **F12 — key index semantics.** `aid_sig` entries are indexed signatures; the
  index is the key's position in `k` of the event at `kel_seq_num`. The PR
  says this in the validation steps but not where the map is generated.

## Limits

- **In-process network.** OOBIs point at `witness1:3232`, which only exists
  inside the test process. Fixtures on disk can't be resolved by another
  tool.
- **Only the signer has an OOBI.** Organisation AIDs other than Fabrikam and
  Dana are still witness-less; that is the gap F5 describes, and Phase 4
  feeds their KELs from fixtures.
- **Claim signer is a test certificate**, not on any trust list, so readers
  report the manifest as valid, not trusted.
