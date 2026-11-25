# Findings for PR 269 (`cawg.vlei`)

This is the consolidated result of Phases 0–5. The testbed is an
independent Rust implementation of the PR (keriox, c2pa-rs). It builds a
vLEI chain (GLEIF Root → GEDA → QVI → legal entity → people), signs C2PA
assets with each kind of `cawg.vlei` signer, and validates them by following
`validating.adoc` step by step.

- **PR text checked:** head `464ee8a9` of
  [decentralized-identity/cawg-identity-assertion#269](https://github.com/decentralized-identity/cawg-identity-assertion/pull/269).
- **Testbed:** commit `4368cf3`. Every finding below names the test that
  reproduces it; run them with `cargo test --workspace`.

The **Thread** column says whether the PR discussion already covers a
finding:
- **review** means the existing review on the PR (its body and its inline
  suggestions);
- **Essbante** means a comment by Essbante;
- **new** means nobody has raised it yet.

## Summary

| # | Finding | Severity | Thread | Evidence |
|---|---|---|---|---|
| F13 | `signer_aid` is never tied to the credentials | security | review item 1 | `verify.rs::borrowed_credentials_pass_the_steps_as_written` |
| F14 | rotated-out keys still validate | security | review item 3; author agrees on anchored-only; Essbante proposes requiring `anchor_seq_num` | `negative.rs::rotated_keys` (N26, N27) |
| F19 | a bad signature next to valid ones is accepted by a keriox-based validator | security | **new** | `negative.rs` N17 |
| F20 | `signer_aid_oobi` URLs are attacker-chosen and fetched by validators | security | **new** | `negative.rs` N3, N25 |
| F17 | no trust anchor configuration | security | review item 2; Essbante (GEDA delegation, `host-meta.json`) | `verify.rs::wrong_trust_anchor_fails_setup`, N24 |
| F5 | issuers' KELs and TELs have no source | blocks validation | review item 5; Essbante | `chain.rs::full_chain_builds_and_links` (14 KELs, 7 TELs) |
| F1 | the signed bytes are a re-encoding, not the stored bytes | interop | review item 10 | `assets.rs`, `verify.rs::signatures_do_not_cover_the_stored_signer_payload_bytes` |
| F18 | the authorisation dependencies are only referenced, not listed | interop | review item 1; Essbante lists the four cases; author prefers to keep them in the trust model | N8–N11 |
| F16 | the status source is named as "witnesses of the issuing QVI" | interop | review inline suggestion; author: witnesses hold TELs | N20–N22 |
| F15 | the KEL refresh in step 2.b ignores `anchor_seq_num` | interop | **new** | `verify.rs::stale_signer_kel_is_refreshed_for_the_anchor` |
| F9 | the anchor is a seal, and its hash is unnamed | interop | review item 7 | `sign.rs::anchored_signature_records_payload_digest`, N13 |
| F12 | key index semantics are not stated in "Generating" | interop | **new** | N16, N16b |
| F10 | the CDDL doesn't parse | spec | review item 8 | `infra/cddl/vlei-signature-payload.cddl` |
| F6 | embedding an ECR conflicts with the ECR's own `privacyDisclaimer` | governance | Essbante (`generating.adoc:34`) | schema text, `ecr-qvi` and `ecr-le` cases |
| F7, F11 | size: maps are 3.2–7.3 KB | guidance | **new** | `testbed sign` output |
| F8 | authorisation credentials are issued to the QVI | clarification | covered by F18 | N8 |
| F2, F3, F4 | ECR edges, ECR schema ID and `kel_seq_num` key lookup work as the PR says | confirmed | n/a | Phase 0 spikes |

The phase notes (`PHASE0.md` to `PHASE5.md`) describe how each finding was
found. The rest of this file gives the corrected statement of each finding
and the proposed fix.

## Security

### F13: the signer isn't bound to the credentials

A validator that follows every step as written accepts an assertion where
Carol signs with her own keys and embeds Alice's public OOR credential. The
validator then reports the signer as "Alice Example, Chief Financial
Officer".

The author's position is that "dependencies" are covered by the trust model
section. But the trust model lists only links *between credentials*:
issuer/issuee, edges, schemas. None of them ties a credential to
`signer_aid`, so moving the trust model into the normative text would not
close this gap.

**Fix:** "`signer_aid` MUST be the issuee (`a.i`) of the credential in
`role_cred.cred` or, when `role_cred` is absent, of the credential in
`le_cred`." This is step `2.c.signer` in the validator.

### F14: keys rotated out still validate

`generating.adoc` says `kel_seq_num` names the latest establishment event *at
signing time*, but a validator can't know when the asset was signed. In
N26, Alice signs, then rotates her keys. Under the PR's validation text the
old signature still validates, and a later signature re-labelled with the
old `kel_seq_num` is only stopped by the key mismatch (N27b).

The author proposes relying on anchored signatures only. The testbed
supports that: the anchored signature, dated before the rotation, is
accepted, while the unanchored one is rejected.

**Fix:** unless the signature is anchored at an `anchor_seq_num` earlier than
the next establishment event, the event at `kel_seq_num` MUST be the latest
establishment event in the signer's KEL. The validator implements this as
`Policy::reject_superseded_keys`.

### F19: invalid signatures alongside valid ones (new)

Step 4 asks for "signature validation" of each `aid_sig` entry and then a
threshold check. keriox's `Controller::verify` and `KeyConfig::verify` drop
signatures that fail and check the threshold on the rest.

N17 runs keriox on Dana's 2-of-3 map with a third, invalid signature added,
and keriox accepts it. A validator that hands step 4 to its KERI library
inherits that behaviour.

**Fix:** "Every entry of `aid_sig` MUST verify against the key at its index;
otherwise abort. Each index MUST appear at most once."

### F20: OOBIs are attacker-supplied URLs (new)

Step 2.b tells the validator to fetch `signer_aid_oobi`, whose URLs the asset
author chooses. In N3 and N25 the validator made real DNS lookups for the
hosts in the OOBIs. A KEL is self-certifying, so a malicious server can't
forge one, but fetching an attacker's URLs:

- tells the asset author who validates the asset, and when;
- can reach internal hosts (SSRF);
- can serve a different, valid-looking history for a duplicitous AID.

**Fix:** add a security consideration. Validators MAY decline to resolve
OOBIs, or proxy them; they SHOULD prefer KEL state from their own watchers;
and they SHOULD report `cawg.identity.network_traffic_blocked` when they
don't resolve them (review item 11).

### F17: trust anchors

The validator pins GLEIF Root and GEDA. Everything else is derived:
- GEDA must be delegated by Root;
- the QVI credential must be issued by GEDA;
- the QVI's AID must be delegated by GEDA.

Pinning the QVI in place of GEDA fails at setup. The PR should name the
pinned AIDs and these checks.

## Interoperability

### F5: issuer KELs and TELs

The PR's payload carries OOBIs for the signer only. Replaying the full chain
needed 14 KELs and 7 TELs:
- KELs: Root, GEDA, the QVI, the legal entity, and the members of each group;
- TELs: one per credential.

This matches Essbante's point: the spec needs either a discovery mechanism
or embedded evidence. The testbed's `Evidence` bundle
(`fixtures/generated/evidence.json`) is one concrete shape for the embedded
option: KEL CESR streams keyed by AID, `vcp` events keyed by registry, and
TEL events keyed by credential SAID.

### F1: which bytes are signed

c2pa-rs stores `signer_payload` in struct order (`referenced_assertions`,
`sig_type`, `role`). PR 269 signs the core deterministic re-encoding (sorted
keys). In all six real assets, `aid_sig` fails over the stored bytes and
verifies over the re-encoding. The X.509 credential type signs the stored
bytes. The PR has to state its rule, and the c2pa-rs holder interface has to
follow it.

### F18 and F8: authorisation dependencies

The validator needs these checks, and N8–N11 exercise them:
- the authorisation credential is issued by the legal entity and has an
  `le` edge to the presented LE credential;
- it is issued to the role credential's issuer (`I2I`); in practice that
  issuer is the QVI;
- its `AID` claim is the role credential's issuee;
- `LEI`, `personLegalName` and `officialRole` / `engagementContextRole` are
  equal in both credentials;
- the role credential's `auth` edge points at the presented authorisation.

Whether these live in `validating.adoc` or in a normative trust model
section, they have to be stated somewhere normative.

### F16: credential status source (corrected)

The author clarifies that in GLEIF's setup the issuer's witnesses serve the
TELs. The testbed models TEL events anchored in the issuer's KEL and fed in
as evidence; it doesn't run a TEL-serving witness. The remaining problem is
the wording "the witnesses of the issuing QVI". The legal entity issues the
OOR and ECR authorisation credentials and LE-issued ECRs, so their TELs live
with the LE's witnesses. That needs an OOBI for the LE too, which is F5
again.

N20 and N21 also show the open revocation-timing question (review item 4):
status is checked at validation time, so a credential revoked after signing
invalidates earlier assertions.

### F15: KEL refresh and the anchor (new)

Step 2.b refetches the KEL only if `kel_seq_num` is missing. A validator with
a cached KEL from before the anchoring `ixn` then fails step 3, although a
refresh would succeed.

**Fix:** "…are available, and, if `anchor_seq_num` is present, the KEL
contains the event with that sequence number."

### F9: anchor seal and hash

The testbed anchors a digest seal `{"d": <Blake3-256, CESR code E>}`. The
validator selects the hash function from the seal's own CESR code, so the
spec only has to require a digest seal. Pinning one algorithm isn't
necessary. One `ixn` can carry several digest seals, which addresses the
author's concern about KEL growth; the testbed hasn't exercised that.

### F12: key index semantics (new)

`generating.adoc` requires "indexed" signatures but doesn't say what the
index is. Only `validating.adoc` says it's the key's position in `k`. N16
(index out of range) and N16b (swapped indexes) fail at step 4.

**Fix:** state the index rule where the signatures are generated.

### F10: CDDL

The corrected definition, as suggested in the review, parses with the
`cddl` tool, and all six maps validate against it
(`infra/cddl/vlei-signature-payload.cddl`).

## Governance and guidance

### F6: ECR privacy (raised by Essbante)

GLEIF's ECR schema makes the holder solely responsible for presenting the
credential "in a privacy-preserving manner using the mechanisms provided in
the … (IPEX) protocol". `cawg.vlei` instead embeds the full ECR, `u` salts
included, in a manifest anyone can read. This should be checked with GLEIF
before ECR credentials are allowed. The alternative is to limit `cawg.vlei`
to OOR and LE signers.

### F7 and F11: size

Measured map sizes:

| Bundle | Size |
|---|---|
| legal entity only | 3.2 KB |
| ECR issued by the legal entity | 5.2 KB |
| OOR | 6.3 KB |
| ECR issued by a QVI | 7.3 KB |

c2pa-rs reserves space for `signature` before signing, and the testbed
reserves 16 KB. Implementers need a bound or a rule of thumb.

## Not tested

- **Keripy/KERIA interop.** No byte comparison with events produced by
  keripy or KERIA. The TEL vectors come from keriox's tests.
- **Weighted thresholds.** Thresholds given as lists of fractions were not
  tried.
- **Duplicity.** No two witnesses served conflicting KELs for one AID.
- **TEL-serving witnesses.** TELs come only from the evidence bundle.
- **Group identifiers.** No QVI or legal entity rotates keys or has a
  revoked status.
- **CESR 2.0 attachments.** KELs are written with KERI 1.0 events and
  CESR 2.0 attachments; other combinations were not checked.
- **Status codes.** The PR defines none. The validator's step names (`1`,
  `2.b`, `2.c.signer`, …) are one possible basis.
