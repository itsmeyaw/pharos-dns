pub(super) fn unquote(source: &str) -> Result<String, String> {
    let quote = source.chars().next().ok_or("empty quoted string")?;
    if !matches!(quote, '"' | '\'' | '`') || !source.ends_with(quote) || source.len() < 2 {
        return Err("invalid quoted string".into());
    }
    let inner = &source[1..source.len() - 1];
    if quote == '`' {
        return Ok(inner.replace('\r', ""));
    }
    let mut output = Vec::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\n' || ch == '\r' {
            return Err("newline in quoted string".into());
        }
        if ch != '\\' {
            if ch == quote {
                return Err("unescaped quote".into());
            }
            let mut encoded = [0; 4];
            output.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            continue;
        }
        let escaped = chars.next().ok_or("incomplete string escape")?;
        let byte = match escaped {
            'a' => Some(7),
            'b' => Some(8),
            'f' => Some(12),
            'n' => Some(b'\n'),
            'r' => Some(b'\r'),
            't' => Some(b'\t'),
            'v' => Some(11),
            '\\' => Some(b'\\'),
            '\'' if quote == '\'' => Some(b'\''),
            '"' if quote == '"' => Some(b'"'),
            'x' => Some(number(&mut chars, 2, 16)? as u8),
            '0'..='7' => {
                let value = escaped.to_digit(8).ok_or("invalid octal escape")? * 64
                    + number(&mut chars, 2, 8)?;
                Some(u8::try_from(value).map_err(|_| "octal escape exceeds a byte")?)
            }
            'u' | 'U' => {
                let value = number(&mut chars, if escaped == 'u' { 4 } else { 8 }, 16)?;
                let ch = char::from_u32(value).ok_or("invalid Unicode escape")?;
                let mut encoded = [0; 4];
                output.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                None
            }
            _ => return Err(format!("invalid string escape: \\{escaped}")),
        };
        if let Some(byte) = byte {
            output.push(byte);
        }
    }
    String::from_utf8(output).map_err(|_| "non-UTF-8 template strings are unsupported".into())
}

fn number(chars: &mut std::str::Chars<'_>, count: usize, radix: u32) -> Result<u32, String> {
    let mut value = 0;
    for _ in 0..count {
        let digit = chars
            .next()
            .and_then(|ch| ch.to_digit(radix))
            .ok_or("invalid string escape")?;
        value = value * radix + digit;
    }
    Ok(value)
}
