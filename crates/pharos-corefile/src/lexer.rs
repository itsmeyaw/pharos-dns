/// A Corefile token and its source location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    pub file: String,
    pub line: usize,
    pub text: String,
}

/// Split a Corefile into tokens using the CoreDNS lexer rules.
pub fn lex(file: &str, input: &str) -> Vec<Token> {
    let mut chars = input.strip_prefix('\u{feff}').unwrap_or(input).chars();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut start = 1;
    let mut text = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = false;
    for ch in chars.by_ref() {
        if quoted {
            if !escaped && ch == '\\' {
                escaped = true;
                continue;
            }
            if !escaped && ch == '"' {
                tokens.push(Token {
                    file: file.into(),
                    line: start,
                    text: std::mem::take(&mut text),
                });
                quoted = false;
                continue;
            }
            if ch == '\n' {
                line += 1;
            }
            if escaped && ch != '"' {
                text.push('\\');
            }
            text.push(ch);
            escaped = false;
            continue;
        }
        if ch.is_whitespace() {
            if ch == '\r' {
                continue;
            }
            if ch == '\n' {
                line += 1;
                comment = false;
            }
            if !text.is_empty() {
                tokens.push(Token {
                    file: file.into(),
                    line: start,
                    text: std::mem::take(&mut text),
                });
            }
            continue;
        }
        if ch == '#' {
            comment = true;
        }
        if comment {
            continue;
        }
        if text.is_empty() {
            start = line;
            if ch == '"' {
                quoted = true;
                continue;
            }
        }
        text.push(ch);
    }
    if !text.is_empty() {
        tokens.push(Token {
            file: file.into(),
            line: start,
            text,
        });
    }
    tokens
}
