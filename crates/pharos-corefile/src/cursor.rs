use crate::{Error, Token};

/// A source-aware cursor over one Directive's tokens during setup.
pub struct Cursor<'a> {
    file: &'a str,
    tokens: &'a [Token],
    position: Option<usize>,
    nesting: usize,
}

impl<'a> Cursor<'a> {
    /// Start before the first token.
    pub fn new(file: &'a str, tokens: &'a [Token]) -> Self {
        Self {
            file,
            tokens,
            position: None,
            nesting: 0,
        }
    }

    /// Load the next token without regard to line boundaries.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        let next = self.position.map_or(0, |position| position + 1);
        if next < self.tokens.len() {
            self.position = Some(next);
            true
        } else {
            false
        }
    }

    /// Load the next token only if it is on the current line.
    pub fn next_arg(&mut self) -> bool {
        match self.position {
            None => self.next(),
            Some(position) => {
                let Some(next) = self.tokens.get(position + 1) else {
                    return false;
                };
                let current = &self.tokens[position];
                if current.file == next.file
                    && current.line + current.text.matches('\n').count() == next.line
                {
                    self.next()
                } else {
                    false
                }
            }
        }
    }

    /// Load the next token only if it starts a new source line.
    pub fn next_line(&mut self) -> bool {
        match self.position {
            None => self.next(),
            Some(position) => {
                let Some(next) = self.tokens.get(position + 1) else {
                    return false;
                };
                let current = &self.tokens[position];
                if crate::parser::new_line(current, next) {
                    self.next()
                } else {
                    false
                }
            }
        }
    }

    /// Enter or continue a nested brace-delimited block.
    pub fn next_block(&mut self) -> bool {
        if self.nesting > 0 {
            if !self.next() {
                return false;
            }
            if self.val() == "{" {
                self.position = self.position.and_then(|position| position.checked_sub(1));
            } else if self.val() == "}" {
                self.nesting -= 1;
                return false;
            } else {
                return true;
            }
        }
        if !self.next_arg() {
            return false;
        }
        if self.val() != "{" {
            self.position = self.position.and_then(|position| position.checked_sub(1));
            return false;
        }
        if !self.next() || self.val() == "}" {
            return false;
        }
        self.nesting += 1;
        true
    }

    /// Current token text, or an empty string before the first token.
    pub fn val(&self) -> &str {
        self.position
            .map_or("", |position| &self.tokens[position].text)
    }

    /// Current source file, falling back to the initial filename.
    pub fn file(&self) -> &str {
        self.position.map_or(self.file, |position| {
            let file = &self.tokens[position].file;
            if file.is_empty() { self.file } else { file }
        })
    }

    /// Current source line, or zero before the first token.
    pub fn line(&self) -> usize {
        self.position
            .map_or(0, |position| self.tokens[position].line)
    }

    /// Fill targets with same-line arguments, leaving missing targets unchanged.
    pub fn args(&mut self, targets: &mut [&mut String]) -> bool {
        for target in targets {
            if !self.next_arg() {
                return false;
            }
            **target = self.val().to_owned();
        }
        true
    }

    /// Consume the remaining same-line arguments, stopping before an opening brace.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut args = Vec::new();
        while self.next_arg() {
            if self.val() == "{" {
                self.position = self.position.and_then(|position| position.checked_sub(1));
                break;
            }
            args.push(self.val().to_owned());
        }
        args
    }

    /// Create an error at the current token.
    pub fn error(&self, message: impl Into<String>) -> Error {
        Error {
            file: self.file().to_owned(),
            line: self.line(),
            message: message.into(),
        }
    }

    /// Create the standard missing or unexpected argument error.
    pub fn arg_err(&self) -> Error {
        if self.val() == "{" {
            self.error("Unexpected token '{', expecting argument")
        } else {
            self.error(format!(
                "Wrong argument count or unexpected line ending after '{}'",
                self.val()
            ))
        }
    }
}
