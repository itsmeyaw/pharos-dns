use std::{collections::BTreeMap, fmt};

use crate::{Token, lex};

/// Parsed Server Block keys and Directive tokens, grouped by Directive name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerBlock {
    pub keys: Vec<String>,
    pub directives: BTreeMap<String, Vec<Token>>,
}

/// A Corefile error with the source location of the offending token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub file: String,
    pub line: usize,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl std::error::Error for Error {}

fn new_line(previous: &Token, current: &Token) -> bool {
    previous.file != current.file
        || previous.line + previous.text.matches('\n').count() < current.line
}

/// Parse a Corefile without validating Plugin-specific Directive names or arguments.
pub fn parse(file: &str, input: &str) -> Result<Vec<ServerBlock>, Error> {
    parse_with_env(file, input, |name| std::env::var(name).ok())
}

/// Parse using an injectable environment lookup.
pub fn parse_with_env(
    file: &str,
    input: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<ServerBlock>, Error> {
    Parser {
        tokens: lex(file, input),
        pos: 0,
        file,
        lookup: &lookup,
    }
    .parse_all()
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    lookup: &'a dyn Fn(&str) -> Option<String>,
}

impl Parser<'_> {
    fn substitute(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for (start, end) in [("{%", "%}"), ("{$", "}")] {
            let mut remaining = 0;
            while let Some(relative) = result[remaining..].find(start) {
                let index = remaining + relative;
                let Some(end_offset) = result[index..].find(end) else {
                    break;
                };
                let end_index = index + end_offset;
                if end_index <= index + start.len() {
                    break;
                }
                let name = &result[index + start.len()..end_index];
                let value = (self.lookup)(name).unwrap_or_default();
                result.replace_range(index..end_index + end.len(), &value);
                remaining = index + value.len();
            }
        }
        result
    }
    fn error(&self, message: &str) -> Error {
        let token = self.tokens.get(self.pos).or_else(|| self.tokens.last());
        Error {
            file: token.map_or(self.file, |t| &t.file).into(),
            line: token.map_or(1, |t| t.line),
            message: message.into(),
        }
    }

    fn parse_all(&mut self) -> Result<Vec<ServerBlock>, Error> {
        let mut blocks = Vec::new();
        while self.pos < self.tokens.len() {
            let block = self.block()?;
            if !block.keys.is_empty() {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    fn block(&mut self) -> Result<ServerBlock, Error> {
        let mut block = ServerBlock::default();
        let mut expecting = false;
        while self.pos < self.tokens.len() {
            let text = self.substitute(&self.tokens[self.pos].text);
            if text == "{" {
                if expecting {
                    return Err(self.error("expected another Server Block Key"));
                }
                break;
            }
            if !text.is_empty() {
                expecting = text.ends_with(',');
                block
                    .keys
                    .push(text.strip_suffix(',').unwrap_or(&text).into());
            }
            self.pos += 1;
            if self.pos == self.tokens.len() {
                if expecting {
                    return Err(self.error("unexpected end of input"));
                }
                return Ok(block);
            }
            if !expecting && new_line(&self.tokens[self.pos - 1], &self.tokens[self.pos]) {
                break;
            }
        }
        let braced = self.tokens[self.pos].text == "{";
        if braced {
            self.pos += 1;
        }
        while self.pos < self.tokens.len() && self.tokens[self.pos].text != "}" {
            self.directive(&mut block)?;
        }
        if braced {
            if self.pos == self.tokens.len() {
                return Err(self.error("expected closing brace"));
            }
            self.pos += 1;
        } else if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        Ok(block)
    }

    fn directive(&mut self, block: &mut ServerBlock) -> Result<(), Error> {
        let name = self.substitute(&self.tokens[self.pos].text);
        let mut items = vec![self.tokens[self.pos].clone()];
        self.pos += 1;
        let mut nesting = 0usize;
        while self.pos < self.tokens.len() {
            let token = &self.tokens[self.pos];
            if token.text == "{" {
                nesting += 1;
            } else if nesting == 0 && new_line(&self.tokens[self.pos - 1], token) {
                break;
            } else if token.text == "}" {
                if nesting == 0 {
                    return Err(self.error("unexpected closing brace"));
                }
                nesting -= 1;
            }
            let mut token = token.clone();
            token.text = self.substitute(&token.text);
            items.push(token);
            self.pos += 1;
        }
        if nesting != 0 {
            return Err(self.error("unexpected end of input"));
        }
        block.directives.entry(name).or_default().extend(items);
        Ok(())
    }
}
