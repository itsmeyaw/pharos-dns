//! Percent-encoding exactly as Go's `net/url` does it for the Nomad request line.

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn percent(out: &mut String, byte: u8) {
    out.push('%');
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 15)]));
}

// Go net/url url.go shouldEscape: letters, digits and `-_.~` are never escaped.
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// Go net/url `PathEscape`: escape `text` as one path segment.
pub(super) fn path_segment(out: &mut String, text: &[u8]) {
    for &byte in text {
        // Go net/url url.go shouldEscape, encodePathSegment: `$&+=:@` stay, `/;,?` and everything else escape.
        if unreserved(byte) || matches!(byte, b'$' | b'&' | b'+' | b'=' | b':' | b'@') {
            out.push(char::from(byte));
        } else {
            percent(out, byte);
        }
    }
}

/// Go net/url `QueryEscape`: escape `text` as a query component.
pub(super) fn query_component(out: &mut String, text: &[u8]) {
    for &byte in text {
        match byte {
            // Go net/url url.go escape, encodeQueryComponent: a space becomes `+`.
            b' ' => out.push('+'),
            byte if unreserved(byte) => out.push(char::from(byte)),
            byte => percent(out, byte),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> String {
        let mut out = String::new();
        path_segment(&mut out, text.as_bytes());
        out
    }

    fn query(text: &str) -> String {
        let mut out = String::new();
        query_component(&mut out, text.as_bytes());
        out
    }

    // Go net/url url_test.go TestPathEscape and TestQueryEscape: reserved bytes differ per mode.
    #[test]
    fn path_segments_keep_only_what_go_keeps() {
        assert_eq!(path("redis"), "redis");
        assert_eq!(path("a b"), "a%20b");
        assert_eq!(path("a/b"), "a%2Fb");
        assert_eq!(path("a;b,c?d"), "a%3Bb%2Cc%3Fd");
        assert_eq!(path("$&+=:@"), "$&+=:@");
        assert_eq!(path("%2e"), "%252e");
        assert_eq!(path(".."), "..");
        assert_eq!(path("\\.\\."), "%5C.%5C.");
        assert_eq!(path("é"), "%C3%A9");
        assert_eq!(path("a#b"), "a%23b");
    }

    #[test]
    fn query_components_escape_reserved_bytes() {
        assert_eq!(query("default"), "default");
        assert_eq!(
            query("Tags not contains candidate"),
            "Tags+not+contains+candidate"
        );
        assert_eq!(query("a&b=c"), "a%26b%3Dc");
        assert_eq!(query("a+b"), "a%2Bb");
        assert_eq!(query("$&+,/:;=?@"), "%24%26%2B%2C%2F%3A%3B%3D%3F%40");
        assert_eq!(query("ü"), "%C3%BC");
        assert_eq!(query("a\r\nb"), "a%0D%0Ab");
    }
}
