//! Byte-exact reference events. The `vcp` is in the format keripy writes
//! since its serder rewrite (`d` = `i`, nonce in `n`); `iss` / `rev` are the
//! simple (no-backer) issuance and revocation events. All three are taken
//! from keriox's KERI 1.0 TEL tests before that TEL was removed
//! (keriox commit 2703b426^).

use vlei_chain::tel::{self, TelEvent};

const VCP: &str = r#"{"v":"KERI10JSON000113_","t":"vcp","d":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPXBsg2LvxA","i":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPXBsg2LvxA","ii":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":["NB"],"bt":"0","b":[],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}"#;
const ISS: &str = r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"EELqqdELW6CUVWfmsbt5sxfQfEOykyOWdUV12biBR4TH","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"2021-01-01T00:00:00.000000+00:00"}"#;
const REV: &str = r#"{"v":"KERI10JSON000120_","t":"rev","d":"EGtAthwVjf0O9qsSz0HR-C63DSEBhn3kRoxvmuRFECOQ","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EB2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00.000000+00:00"}"#;

#[test]
fn vcp_matches_reference_bytes() {
    let e = tel::vcp("DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM", "A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U").unwrap();
    assert_eq!(std::str::from_utf8(e.raw()).unwrap(), VCP);
}

#[test]
fn iss_matches_reference_bytes() {
    let e = tel::iss("DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM", "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw", "2021-01-01T00:00:00.000000+00:00").unwrap();
    assert_eq!(std::str::from_utf8(e.raw()).unwrap(), ISS);
}

#[test]
fn rev_matches_reference_bytes() {
    let e = tel::rev(
        "DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM",
        "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw",
        "EB2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg",
        "2021-01-01T00:00:00.000000+00:00",
    )
    .unwrap();
    assert_eq!(std::str::from_utf8(e.raw()).unwrap(), REV);
}

#[test]
fn reference_events_parse_and_tampering_is_caught() {
    for raw in [VCP, ISS, REV] {
        TelEvent::parse(raw.as_bytes()).unwrap();
        let tampered = raw.replace("\"s\":\"0\"", "\"s\":\"2\"").replace("\"s\":\"1\"", "\"s\":\"2\"");
        assert!(TelEvent::parse(tampered.as_bytes()).is_err(), "{raw}");
    }
}
