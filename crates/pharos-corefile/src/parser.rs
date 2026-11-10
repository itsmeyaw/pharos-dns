use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

use crate::{ServerBlockKey, Token, lex, normalize_key};

/// Parsed Server Block keys and Directive tokens, grouped by Directive name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerBlock {
    keys: Vec<String>,
    key_sources: Vec<Token>,
    pub directives: BTreeMap<String, Vec<Token>>,
}

impl ServerBlock {
    /// The Server Block's original, environment-expanded keys.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// Validate and normalize keys, retaining source locations for errors.
    pub fn normalize_keys(&self) -> Result<Vec<ServerBlockKey>, Error> {
        let mut normalized = Vec::new();
        for (key, source) in self.keys.iter().zip(&self.key_sources) {
            normalized.extend(normalize_key(key).map_err(|message| Error {
                file: source.file.clone(),
                line: source.line,
                message,
            })?);
        }
        Ok(normalized)
    }
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
        snippets: BTreeMap::new(),
        snippet_expansions: 0,
        file_expansions: 0,
    }
    .parse_all()
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    file: &'a str,
    lookup: &'a dyn Fn(&str) -> Option<String>,
    snippets: BTreeMap<String, Vec<Token>>,
    snippet_expansions: usize,
    file_expansions: usize,
}

impl Parser<'_> {
    fn substitute(&self, text: &str) -> Result<String, Error> {
        let mut result = text.to_owned();
        for (start, end) in [("{%", "%}"), ("{$", "}")] {
            let mut seen = BTreeSet::new();
            while let Some(index) = result.find(start) {
                let Some(end_offset) = result[index..].find(end) else {
                    break;
                };
                let end_index = index + end_offset;
                if end_index <= index + start.len() {
                    break;
                }
                let name = &result[index + start.len()..end_index];
                let value = (self.lookup)(name).unwrap_or_default();
                let reference = &result[index..end_index + end.len()];
                // shortcut: bound expansion to 10,000 steps and 16 MiB; upgrade for larger configurations.
                let occurrences = result.matches(reference).count();
                let size = result.len() - occurrences * reference.len();
                if seen.len() >= 10_000
                    || !seen.insert(result.clone())
                    || value
                        .len()
                        .checked_mul(occurrences)
                        .and_then(|n| n.checked_add(size))
                        .is_none_or(|n| n > 16 * 1024 * 1024)
                {
                    return Err(self.error("environment expansion limit or cycle"));
                }
                result = result.replace(reference, &value);
            }
        }
        Ok(result)
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
            let text = self.substitute(&self.tokens[self.pos].text)?;
            if text == "import"
                && (self.pos == 0 || new_line(&self.tokens[self.pos - 1], &self.tokens[self.pos]))
            {
                self.import()?;
                continue;
            }
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
                block.key_sources.push(self.tokens[self.pos].clone());
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
        if self.pos == self.tokens.len() {
            return Ok(block);
        }
        if block.keys.len() == 1 && block.keys[0].starts_with('(') && block.keys[0].ends_with(')') {
            let name = block.keys[0][1..block.keys[0].len() - 1].to_owned();
            if self.tokens[self.pos].text != "{" {
                return Err(self.error("expected snippet opening brace"));
            }
            if self.snippets.contains_key(&name) {
                return Err(self.error("duplicate snippet"));
            }
            self.pos += 1;
            let start = self.pos;
            let mut nesting = 1;
            while self.pos < self.tokens.len() && nesting > 0 {
                match self.tokens[self.pos].text.as_str() {
                    "{" => nesting += 1,
                    "}" => nesting -= 1,
                    _ => {}
                }
                self.pos += 1;
            }
            if nesting != 0 {
                return Err(self.error("expected snippet closing brace"));
            }
            let tokens = self.tokens[start..self.pos - 1].to_vec();
            for (i, token) in tokens.iter().enumerate() {
                if token.text == "import"
                    && (i == 0 || new_line(&tokens[i - 1], token))
                    && let Some(next) = tokens.get(i + 1)
                    && self.substitute(&next.text)? == name
                {
                    return Err(self.error("recursive snippet"));
                }
            }
            self.snippets.insert(name, tokens);
            return Ok(ServerBlock::default());
        }
        let braced = self.tokens[self.pos].text == "{";
        if braced {
            self.pos += 1;
        }
        while self.pos < self.tokens.len() && self.tokens[self.pos].text != "}" {
            if self.tokens[self.pos].text == "import" {
                self.import()?;
                continue;
            }
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
        let name = self.substitute(&self.tokens[self.pos].text)?;
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
            } else if token.text == "import" && new_line(&self.tokens[self.pos - 1], token) {
                self.import()?;
                continue;
            }
            let mut token = token.clone();
            token.text = self.substitute(&token.text)?;
            items.push(token);
            self.pos += 1;
        }
        if nesting != 0 {
            return Err(self.error("unexpected end of input"));
        }
        block.directives.entry(name).or_default().extend(items);
        Ok(())
    }

    fn import(&mut self) -> Result<(), Error> {
        let start = self.pos;
        let Some(arg) = self.tokens.get(start + 1) else {
            return Err(self.error("import requires an argument"));
        };
        if arg.file != self.tokens[start].file
            || arg.line != self.tokens[start].line + self.tokens[start].text.matches('\n').count()
        {
            return Err(self.error("import requires an argument"));
        }
        let pattern = self.substitute(&arg.text)?;
        if pattern.is_empty() {
            return Err(self.error("import requires a non-empty path"));
        }
        if let Some(next) = self.tokens.get(start + 2)
            && next.file == arg.file
            && next.line == arg.line + arg.text.matches('\n').count()
        {
            return Err(self.error("import takes only one argument"));
        }
        let imported = if let Some(tokens) = self.snippets.get(&pattern) {
            self.snippet_expansions += 1;
            if self.snippet_expansions > 10_000 {
                return Err(self.error("snippet import limit exceeded"));
            }
            tokens.clone()
        } else {
            self.file_expansions += 1;
            if self.file_expansions > 100_000 {
                return Err(self.error("file import limit exceeded"));
            }
            let base = Path::new(&self.tokens[start].file);
            let base = if base.is_absolute() {
                base.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|e| self.error(&e.to_string()))?
                    .join(base)
            };
            let path = if Path::new(&pattern).is_absolute() {
                pattern.clone().into()
            } else {
                base.parent().unwrap_or(Path::new("/")).join(&pattern)
            };
            let glob_pattern = path.to_string_lossy();
            if glob_pattern.matches('*').count() > 1
                || glob_pattern.matches('?').count() > 1
                || (glob_pattern.contains('[') && glob_pattern.contains(']'))
            {
                return Err(self.error("too many import wildcards"));
            }
            let mut translated = String::new();
            let mut chars = glob_pattern.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    let Some(escaped) = chars.next().filter(|c| *c != '/') else {
                        return Err(self.error("invalid import pattern"));
                    };
                    translated.push_str(&glob::Pattern::escape(&escaped.to_string()));
                } else {
                    translated.push(ch);
                }
            }
            let paths = glob::glob(&translated).map_err(|e| self.error(&e.to_string()))?;
            let mut imported = Vec::new();
            let mut count = 0;
            for path in paths.flatten() {
                count += 1;
                let contents = std::fs::read(&path).map_err(|e| self.error(&e.to_string()))?;
                imported.extend(lex(
                    &path.to_string_lossy(),
                    &crate::lexer::decode(&contents),
                ));
            }
            if count == 0 && !glob_pattern.contains(['*', '?', '[', ']']) {
                return Err(self.error("import file not found"));
            }
            imported
        };
        self.tokens.splice(start..start + 2, imported);
        Ok(())
    }
}
