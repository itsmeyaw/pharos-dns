//! Port of flynn/go-shlex `Split`, which coredns/caddy `SplitCommandAndArgs` uses on Unix.

use std::str::Chars;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Class {
    Char,
    Space,
    DoubleQuote,
    SingleQuote,
    Escape,
    Comment,
    Unknown,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Start,
    InWord,
    Escaping,
    EscapingQuoted,
    QuotedEscaping,
    Quoted,
    Comment,
}

enum Token {
    Word(String),
    Comment,
}

// go-shlex v0.0.0-20150515145356 shlex.go `RUNE_*`: the default ASCII classifier.
fn classify(c: char) -> Class {
    match c {
        'a'..='z' | 'A'..='Z' | '0'..='9' => Class::Char,
        '.' | '_' | '-' | ',' | '/' | '@' | '$' | '*' | '(' | ')' | '+' | '=' | '>' | '<' | ':'
        | ';' | '&' | '^' | '%' | '~' | '|' | '!' | '?' | '[' | ']' | '{' | '}' => Class::Char,
        ' ' | '\t' | '\r' | '\n' => Class::Space,
        '"' => Class::DoubleQuote,
        '\'' => Class::SingleQuote,
        '\\' => Class::Escape,
        '#' => Class::Comment,
        _ => Class::Unknown,
    }
}

fn unknown(c: char) -> String {
    format!("Unknown rune: {}", c as u32)
}

// go-shlex `Tokenizer.scanStream`: one state-machine pass per token.
fn scan(chars: &mut Chars<'_>) -> Result<Option<Token>, String> {
    let mut state = State::Start;
    let mut value = String::new();
    loop {
        let Some(c) = chars.next() else {
            return match state {
                State::Start => Ok(None),
                State::InWord => Ok(Some(Token::Word(value))),
                State::Comment => Ok(Some(Token::Comment)),
                State::Escaping | State::EscapingQuoted => {
                    Err("EOF found after escape character".to_owned())
                }
                State::QuotedEscaping | State::Quoted => {
                    Err("EOF found when expecting closing quote.".to_owned())
                }
            };
        };
        let class = classify(c);
        match state {
            State::Start => match class {
                Class::Char => {
                    value.push(c);
                    state = State::InWord;
                }
                Class::Space => {}
                Class::DoubleQuote => {
                    state = State::QuotedEscaping;
                }
                Class::SingleQuote => {
                    state = State::Quoted;
                }
                Class::Escape => {
                    state = State::Escaping;
                }
                Class::Comment => state = State::Comment,
                Class::Unknown => return Err(unknown(c)),
            },
            State::InWord => match class {
                Class::Char | Class::Comment => value.push(c),
                Class::Space => return Ok(Some(Token::Word(value))),
                Class::DoubleQuote => state = State::QuotedEscaping,
                Class::SingleQuote => state = State::Quoted,
                Class::Escape => state = State::Escaping,
                Class::Unknown => return Err(unknown(c)),
            },
            State::Escaping | State::EscapingQuoted => {
                if class == Class::Unknown {
                    return Err(unknown(c));
                }
                value.push(c);
                state = if state == State::Escaping {
                    State::InWord
                } else {
                    State::QuotedEscaping
                };
            }
            State::QuotedEscaping => match class {
                Class::DoubleQuote => state = State::InWord,
                Class::Escape => state = State::EscapingQuoted,
                _ => value.push(c),
            },
            State::Quoted => match class {
                Class::SingleQuote => state = State::InWord,
                _ => value.push(c),
            },
            State::Comment => {
                if c == '\n' {
                    return Ok(Some(Token::Comment));
                }
            }
        }
    }
}

/// Split on shell-style quoting, escaping and `#` comments; never runs a shell.
pub(super) fn split(input: &str) -> Result<Vec<String>, String> {
    let mut chars = input.chars();
    let mut words = Vec::new();
    while let Some(token) = scan(&mut chars)? {
        if let Token::Word(word) = token {
            words.push(word);
        }
    }
    Ok(words)
}
