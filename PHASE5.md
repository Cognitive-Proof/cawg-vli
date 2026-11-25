# Phase 5: negative tests

`crates/vlei-verify/tests/negative.rs` starts from valid assertions and
breaks one thing at a time. Each case checks two things: that the validator
rejects it, and that it rejects it at the right PR 269 step (the
`VerifyError::step` names from Phase 4). A rejection at the wrong step fails
the test, even if the assertion is rejected.

Most cases edit the decoded `vlei-signature-payload-map` or `signer_payload`
and validate the result directly. A few change the world around the
assertion instead: revocations, key rotation, missing evidence, or a
tampered asset.

To see every rejection with its reason:

```bash
cargo test -p vlei-verify --test negative -- --nocapture --test-threads 1
```

## Cases

| # | What is broken | Rejected at | Reason given |
|---|---|---|---|
| N1 | `sig_type` is `cawg.x509.cose` | `1` | sig_type is not `cawg.vlei` |
| N2 | `signature` is an empty CBOR map; N2b: not CBOR | `2.a` | missing field `signer_aid`; invalid type |
| N3 | `kel_seq_num` 7 (no such event) | `2.b` | keys at sn 7 not available (after trying the OOBI) |
| N3b | `kel_seq_num` 1, Alice's anchoring `ixn` (not an establishment event) | `2.b` | keys at sn 1 not available |
| N4 | `qvi_cred` replaced by the LE credential | `2.c.qvi` | schema Le, expected Qvi |
| N5 | LEI edited in `le_cred`, SAIDs not recomputed | `2.c.i` | SAID of `a` does not match |
| N6 | role credential's `s` changed to an unknown schema | `2.c.ii` | unknown schema |
| N7 | forged OOR (Alice as CEO) with valid SAIDs and schema, never issued | `2.c.ii` | no TEL for the credential |
| N8 | Dana's OOR presented with Alice's authorisation | `2.c.ii.auth` | `auth` edge doesn't point at it |
| N9 | LE-issued ECR (Carol) with a non-empty `auth_cred` | `2.c.ii.auth` | must be empty |
| N10 | QVI-issued ECR (Bob) with `auth_cred` empty | `2.c.ii.auth` | credential is empty |
| N11 | OOR presented with an ECR authorisation | `2.c.ii.auth` | schema EcrAuth, expected OorAuth |
| N12 | Alice drops `role_cred` | `2.c.signer` | signer is not the legal entity |
| N13 | anchored case, `anchor_seq_num` 0 (inception); N13b: anchor claimed on an unanchored signature | `3` | event does not anchor the payload digest |
| N14 | Dana (2-of-3) with one signature | `4` | threshold not met |
| N15 | Dana with the same signature twice | `4` | repeats key 0 |
| N16 | Alice's signature re-indexed to key 1 (out of range); N16b: Dana's two indexes swapped | `4` | names key 1 / does not verify with key 1 |
| N17 | Dana with her two valid signatures plus a third over other data | `4` | `aid_sig[2]` does not verify (F19) |
| N18 | `signer_payload.roles` changed after signing; N18b: same, anchored case | `4`; `3` | signature / anchor does not cover it |
| N19 | `aid_sig` empty | `4` | aid_sig is empty |
| N20 | Alice's OOR revoked after she signed | `2.c.ii` | credential is revoked |
| N21 | the LE credential revoked: Carol (LE-issued ECR) now fails | `2.c.i` | credential is revoked |
| N22 | evidence lacks the LE credential's TEL | `2.c.i` | TEL not available |
| N23 | evidence lacks the QVI's KEL | `2.c.qvi` | KEL of the QVI not available |
| N24 | evidence lacks GLEIF Root's KEL | `setup` | KEL of Root not available |
| N25 | no KEL for Alice, and her only OOBI is unreachable | `2.b` | keys not available after trying every OOBI |
| N26 | Alice rotates her keys after signing (no anchor) | `2.b` | signing keys (sn 0) replaced at sn 2 |
| N27 | after rotating, a new signature re-labelled with `kel_seq_num` 0; N27b: same with the lax policy | `2.b`; `4` | keys replaced / does not verify with the sn 0 key |
| N28 | one byte of the role text edited inside the signed PNG | `c2pa` | manifest validation state Invalid |

The baseline is checked too: before any change, all six Phase 3 cases
validate with the same verifier. So does the rotation counterpart to N26: an
anchored signature dated before the rotation is accepted, with a note.

Earlier phases already cover some of this ground: the borrowed credential
(F13) in `verify.rs`, a wrong trust anchor and stale KELs (Phase 4), and the
c2pa-rs encoding mismatch (F1).

## What the cases show for PR 269

- **F19 confirmed.** N17 also runs keriox's own `Controller::verify` on the
  same map, and it succeeds: keriox drops the bad signature and counts the
  other two. A validator that delegates step 4 to keriox, as the PR's wording
  allows, accepts N17. The PR needs "every `aid_sig` entry SHALL verify".
- **F14 is concrete.** N26 and the lax half of N27 show that, read
  literally, the PR accepts signatures from keys the signer has since rotated
  away. KERI's anchoring gives a principled exception, and the validator
  applies it: the anchored signature dated before the rotation is accepted.
- **F20: OOBIs are attacker-supplied URLs.** `signer_aid_oobi` comes from the
  asset, and step 2.b tells the verifier to fetch it. In N3 and N25 the
  validator made real DNS lookups for `witness1` and `witness9` while trying
  them. Content from a malicious witness can't forge a KEL, because KELs are
  self-certifying. But fetching attacker-chosen URLs:
  - lets an asset author track who validates it;
  - can be aimed at internal hosts (SSRF);
  - can return a different but valid-looking history for a duplicitous AID.

  The PR should add a security consideration: verifiers may restrict or
  proxy OOBI resolution, and prefer watcher-backed KEL state over the
  assertion's own OOBIs.
- **The vLEI signature doesn't cover the map.** N28 shows that the embedded
  credentials are protected only by the C2PA claim signature (the X.509
  claim signer), not by the vLEI signature, which covers `signer_payload`
  only. This is how identity assertions are designed, but together with F13
  it means anyone who builds a manifest can embed any credentials. The signer
  check (`2.c.signer`) is what stops that.

## Coverage of the validation steps

Every step name the validator uses is reached by at least one negative case:
`setup`, `c2pa`, `1`, `2.a`, `2.b`, `2.c.qvi`, `2.c.i`, `2.c.ii`,
`2.c.ii.auth`, `2.c.signer`, `3`, `4`.

The whole workspace (41 tests) passes.

## Not covered

- **Weighted thresholds** (`kt` as a list of fractions). Every signer uses a
  numeric threshold. keriox supports weighted thresholds, but the testbed
  never creates one.
- **Duplicity.** That would need two witnesses serving conflicting KELs for
  one AID. The single in-process witness can't do it.
- **Schema-invalid credentials with valid SAIDs.** Such a credential is
  never issued, so it fails at the TEL check (as in N7) before schema
  validation would matter. Schema validation has its own tests in
  `vlei-chain`.
- **Revocation and rotation of group identifiers** (QVI, LE). Only a
  person's rotation and credential revocations are exercised.
