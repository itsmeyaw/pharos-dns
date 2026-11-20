use super::*;

// RFC 9110 §5.6.7: the example IMF-fixdate.
const DATE: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[test]
fn http_date_parses_the_rfc_9110_example() {
    assert_eq!(http_date(DATE), Some(at(784_111_777)));
}

#[test]
fn http_date_rejects_other_shapes() {
    for text in [
        "",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun, 06 Nov 1994 08:49:37 GMT ",
        "Sun, 06 Nov 94 08:49:37 GMT",
        "Sun, 06 Nov 1994 25:49:37 GMT",
        "Sun, 06 Nov 1994 08-49-37 GMT",
        "Sun, 06 Foo 1994 08:49:37 GMT",
        "Sun, +6 Nov 1994 08:49:37 GMT",
    ] {
        assert_eq!(http_date(text), None, "{text:?}");
    }
}

#[test]
fn retry_delay_honours_seconds_and_dates_within_bounds() {
    let now = at(784_111_777 - 10);
    assert_eq!(retry_delay(None, now), POLL);
    assert_eq!(retry_delay(Some("7"), now), Duration::from_secs(7));
    assert_eq!(retry_delay(Some("0"), now), Duration::from_secs(1));
    assert_eq!(retry_delay(Some("3600"), now), Duration::from_secs(30));
    assert_eq!(retry_delay(Some("soon"), now), POLL);
    assert_eq!(retry_delay(Some(DATE), now), Duration::from_secs(10));
    assert_eq!(retry_delay(Some(DATE), at(0)), Duration::from_secs(30));
    assert_eq!(
        retry_delay(Some(DATE), at(784_111_777 + 60)),
        Duration::from_secs(1)
    );
}
