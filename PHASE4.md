# Phase 4: the validator

`crates/vlei-verify` validates `cawg.vlei` identity assertions by following
PR 269's `validating.adoc` (at PR head `464ee8a9`) step by step. It uses no
private keys and nothing from the signer's side. It starts from:

- **`Trust`** (`trust.json`): the pinned GLEIF Root and GEDA AIDs and the
  installed schema SAIDs. PR 269 assumes this setup but does not define it.
- **`Evidence`** (`evidence.json`): public KELs, registry inceptions and TELs.
  These stand in for witnesses and watchers. The signer's KEL is taken from
  here if present; otherwise it is fetched from `signer_aid_oobi`.

Every rejection names the step it comes from (`VerifyError::step`), so the
negative tests in Phase 5 can check where each bad assertion fails, not just
that it fails.

## Steps

| Step | What the validator checks | In the PR? |
|---|---|---|
| `setup` | Each schema SAID matches the pinned one and recomputes from the schema content. The Root's KEL loads and Root is not delegated. GEDA's KEL loads and GEDA is delegated by the pinned Root. | assumed, not defined |
| `c2pa` | The manifest validates (`Valid` or `Trusted`) before the identity assertion is read. | n/a |
| `1` | `sig_type` is `cawg.vlei`. | yes |
| `2.a` | `signature` decodes as the map. A map not in deterministic encoding is noted but not rejected. | yes |
| `2.b` | The signer's KEL has an establishment event at `kel_seq_num`, and reaches `anchor_seq_num` if that is set. Otherwise the validator tries each OOBI. Keys replaced by a later rotation are rejected unless an earlier anchor dates the signature. | partly (F15, F14) |
| `2.c.qvi` | QVI credential: schema, SAIDs, issued by the pinned GEDA, QVI AID delegated by GEDA, TEL status. | "assumed done at setup" |
| `2.c.i` | LE credential: schema, SAIDs, issued by the QVI, `qvi` edge points at the presented QVI credential, TEL status. | yes |
| `2.c.ii` | Role credential: OOR or ECR chosen by `s`, same LEI as the LE credential, issuer and edges as below, TEL status. | yes |
| `2.c.ii.auth` | Authorisation credential: see the dependency list under F18. For an LE-issued ECR, `auth_cred` is `""`. | by reference (F18) |
| `2.c.signer` | `signer_aid` is the role credential's issuee, or the LE credential's issuee when there is no role credential. | **no (F13)** |
| `3` | The event at `anchor_seq_num` carries a digest seal that binds the serialized `signer_payload`. | yes (F9) |
| `4` | Every `aid_sig` verifies with key `k[index]` of the establishment event at `kel_seq_num`. No key is used twice, and the distinct keys meet `kt`. | yes (F19) |

Each credential check (`credential()`) parses the credential with
`vlei_chain::credential::parse`, which:

- recomputes the SAIDs of `a`, `e`, `r` and the top-level `d`;
- picks the schema by `s` and rejects unknown schemas;
- validates against the schema;
- checks status: the `vcp`, `iss` and (if present) `rev` events must be well
  formed, chained, and anchored in the issuer's KEL. A revoked credential is
  rejected.

## Running it

```bash
cargo run -p testbed-cli -- sign --out fixtures/generated     # also writes trust.json, evidence.json
cargo run -p testbed-cli -- verify --out fixtures/generated   # offline, writes reports/CASE.json
```

```
anchored  VALID  LEI 9845000FABRIKAM00042  OOR  Alice Example, Chief Financial Officer  1/1 sigs  4 creds  anchored at sn 1
ecr-le    VALID  LEI 9845000FABRIKAM00042  ECR  Carol Example, Editor (LE-issued)  1/1 sigs  3 creds
ecr-qvi   VALID  LEI 9845000FABRIKAM00042  ECR  Bob Example, Press Officer (QVI-issued)  1/1 sigs  4 creds
multisig  VALID  LEI 9845000FABRIKAM00042  OOR  Dana Example, Chief Executive Officer  2/3 sigs  4 creds
no-role   VALID  LEI 9845000FABRIKAM00042  legal entity  2/2 sigs  2 creds
oor       VALID  LEI 9845000FABRIKAM00042  OOR  Alice Example, Chief Financial Officer  1/1 sigs  4 creds
```

`testbed verify` runs in a separate process. The in-process witness is gone
by then, so it uses the complete evidence file; the tests below exercise the
OOBI path.

## Tests (`crates/vlei-verify/tests/verify.rs`)

| Test | Shows |
|---|---|
| `every_case_validates` | All six assets validate with a fresh verifier. Alice, Bob, Carol and Dana are left out of the evidence, so their KELs come from their OOBIs. Signer, role, LEI, credential count and signature/key counts match each case. |
| `offline_verifier_needs_the_signer_kel` | With no transport and no KEL for Alice, step `2.b` fails after trying her OOBI. With full evidence, it validates offline. |
| `signatures_do_not_cover_the_stored_signer_payload_bytes` | Verifying over c2pa-rs's stored encoding fails at step `4`, or at `3` for the anchored case (F1). |
| `wrong_trust_anchor_fails_setup` | Pinning the QVI as GEDA fails at `setup`, because the QVI is not delegated by Root. |
| `stale_signer_kel_is_refreshed_for_the_anchor` | The verifier knows Alice's KEL only up to inception. The anchored asset still validates because the validator refetches the KEL by OOBI (F15). |
| `borrowed_credentials_pass_the_steps_as_written` | Carol signs with her own keys but presents Alice's credentials. Validating exactly as the PR is written (`Policy { bind_signer: false }`), it passes and reports the role as Alice's OOR (CFO). With the signer check on, it fails at `2.c.signer`. This confirms F13. |

The whole workspace (36 tests) passes.

## Findings for PR 269 from this phase

- **F13: the signer is never tied to the credentials (security).** The steps
  check that the credentials chain to GLEIF and that `aid_sig` verifies
  against `signer_aid`. Nothing requires `signer_aid` to be the role
  credential's issuee. Credentials are public, so anyone can embed Alice's
  OOR credential and sign with their own AID. Every step in the PR passes and
  the assertion claims to be Alice, CFO. `borrowed_credentials_pass_the_steps_as_written`
  shows this end to end. Proposed text: "`signer_aid` SHALL
  equal the issuee (`a.i`) of the role credential or, when `role_cred` is
  absent, of the LE credential." The validator enforces this as `2.c.signer`.
- **F14: rotated keys.** `kel_seq_num` may name any establishment event, so
  keys that were later rotated out (for example after a compromise) keep
  producing valid signatures. KERI's answer is to date the signature with an
  anchor. The PR should say whether the event at `kel_seq_num` has to be the
  latest establishment event, and that an `anchor_seq_num` earlier than the
  next rotation makes older keys acceptable. The validator rejects superseded
  keys unless anchored that way (`Policy::reject_superseded_keys`).
- **F15: KEL refresh ignores the anchor.** Step 2.b only refetches the KEL when
  `kel_seq_num` is missing. A verifier with a cached KEL from before the
  anchoring event then fails step 3. The refresh condition should also cover
  `anchor_seq_num`.
- **F16: where credential status comes from.** The PR says to check status
  "against the witnesses of the issuing QVI". That is wrong for the
  authorisation credentials and for LE-issued ECRs, which the legal entity
  issues. vLEI registries are also no-backer (`NB`): a TEL has no witnesses
  of its own, and its events are anchored in the issuer's KEL. The text should
  say "the TEL of the credential's registry, anchored in the issuer's KEL",
  and should say how a verifier obtains that TEL (this extends F5).
- **F17: trust anchors are not defined.** The PR assumes the verifier "has
  obtained and validated the credentials of the issuing QVI(s)" but says
  nothing about which AIDs are pinned. The validator pins Root and GEDA and
  derives everything else: the QVI credential must be issued by GEDA, and the
  QVI's AID must be delegated by GEDA. The PR should name the pinned AIDs and
  these two checks.
- **F18: the authorisation dependencies are only referenced.** Step 2.c.ii
  defers to the trust model, which does not list them. The checks needed are:
  - the authorisation is issued by the LE credential's issuee and has an `le`
    edge to the presented LE credential;
  - it is issued to the role credential's issuer (`I2I` on the `auth` edge);
  - its `AID` is the role credential's issuee;
  - `LEI`, `personLegalName` and `officialRole` / `engagementContextRole` are
    equal in both credentials.

  These belong in the validation section.
- **F19: invalid signatures alongside valid ones.** The PR asks for "signature
  validation" of each `aid_sig` entry, then a weight check. keriox's
  `KeyConfig::verify` silently drops signatures that don't verify and checks
  the threshold on the rest. A literal implementation on top of it would
  accept a map that carries a bad signature. The PR should say that every
  entry has to verify and that indexes must be distinct. The validator does
  both.
- **F9, refined.** For step 3 the validator uses the digest seal's own CESR
  derivation code to choose the hash function. That settles the unnamed hash
  algorithm without fixing it in the PR. Suggested wording: "an event whose
  `a` field contains a digest seal `{"d": D}` where `D` is the CESR-encoded
  digest of the serialized `signer_payload`".

## Limits

- **The OOBI path only works in-process.** It is tested against the
  in-process witness; `testbed verify` uses evidence files instead.
- **Keys from earlier rotations aren't exercised.** No case rotates a
  signer's keys, so the F14 rule is implemented but untested. Phase 5 adds a
  rotated signer.
- **Negative cases are thin.** Phase 5 adds them: tampered credentials,
  mismatched edges, revoked credentials, a borrowed credential (F13), a
  missing signature, wrong indexes.
- **The claim certificate is untrusted.** The C2PA check accepts `Valid`. No
  trust list is configured for the throwaway claim certificate.
