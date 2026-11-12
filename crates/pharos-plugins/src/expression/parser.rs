use super::{Binary, Kind, Node, Unary, ValueType};

#[derive(Debug, PartialEq)]
enum Token {
    Integer(i64),
    Float(f64),
    String(String),
    Ident(String),
    Op(String),
    Left,
    Right,
    Comma,
    ListStart,
    ListEnd,
    Current,
    End,
}

pub(super) fn parse(source: &str, variables: &[(&str, ValueType)]) -> Result<Node, String> {
    let mut parser = Parser {
        source,
        variables,
        current: None,
        offset: 0,
        token: Token::End,
    };
    parser.advance()?;
    let node = parser.expression(0)?;
    if parser.token != Token::End {
        return Err(format!("unexpected token {:?}", parser.token));
    }
    if node.kind() == Kind::List {
        return Err("list results are not supported".into());
    }
    Ok(node)
}

struct Parser<'a, 'v> {
    source: &'a str,
    variables: &'v [(&'v str, ValueType)],
    current: Option<Kind>,
    offset: usize,
    token: Token,
}

impl Parser<'_, '_> {
    fn advance(&mut self) -> Result<(), String> {
        let rest = &self.source[self.offset..];
        self.offset += rest.len() - rest.trim_start().len();
        let rest = &self.source[self.offset..];
        let Some(first) = rest.chars().next() else {
            self.token = Token::End;
            return Ok(());
        };
        if first.is_ascii_digit()
            || (first == '.' && rest.as_bytes().get(1).is_some_and(u8::is_ascii_digit))
        {
            let bytes = rest.as_bytes();
            let radix = match (bytes.first(), bytes.get(1)) {
                (Some(b'0'), Some(b'x' | b'X')) => Some(16),
                (Some(b'0'), Some(b'b' | b'B')) => Some(2),
                (Some(b'0'), Some(b'o' | b'O')) => Some(8),
                _ => None,
            };
            if let Some(radix) = radix {
                let mut len = 2;
                while bytes
                    .get(len)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    len += 1;
                }
                let digits = rest[2..len].replace('_', "");
                self.token = Token::Integer(
                    i64::from_str_radix(&digits, radix).map_err(|_| "invalid integer literal")?,
                );
                self.offset += len;
                return Ok(());
            }
            let mut len = 0;
            while bytes
                .get(len)
                .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
            {
                len += 1;
            }
            let mut float = false;
            if bytes.get(len) == Some(&b'.') && bytes.get(len + 1) != Some(&b'.') {
                float = true;
                len += 1;
                while bytes
                    .get(len)
                    .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
                {
                    len += 1;
                }
            }
            if matches!(bytes.get(len), Some(b'e' | b'E')) {
                float = true;
                len += 1;
                if matches!(bytes.get(len), Some(b'+' | b'-')) {
                    len += 1;
                }
                while bytes
                    .get(len)
                    .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
                {
                    len += 1;
                }
            }
            let number = rest[..len].replace('_', "");
            self.token = if float {
                Token::Float(number.parse().map_err(|_| "invalid float")?)
            } else {
                Token::Integer(number.parse().map_err(|_| "invalid integer")?)
            };
            self.offset += len;
        } else if first.is_ascii_alphabetic() || first == '_' {
            let len = rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            self.token = Token::Ident(rest[..len].to_owned());
            self.offset += len;
        } else if first == '`' {
            let mut value = String::new();
            let mut chars = rest[1..].char_indices();
            let mut end = None;
            while let Some((pos, ch)) = chars.next() {
                if ch == '`' {
                    if chars.clone().next().is_some_and(|(_, next)| next == '`') {
                        chars.next();
                        value.push('`');
                    } else {
                        end = Some(pos + 2);
                        break;
                    }
                } else {
                    value.push(ch);
                }
            }
            self.offset += end.ok_or("unterminated raw string")?;
            self.token = Token::String(value);
        } else if first == '\'' || first == '"' {
            let mut value = String::new();
            let mut chars = rest[first.len_utf8()..].char_indices();
            let mut end = None;
            while let Some((pos, ch)) = chars.next() {
                if ch == first {
                    end = Some(pos + first.len_utf8() + ch.len_utf8());
                    break;
                }
                if ch == '\\' {
                    let (_, escaped) = chars.next().ok_or("unterminated string escape")?;
                    value.push(match escaped {
                        'a' => '\u{7}',
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'v' => '\u{b}',
                        '\\' => '\\',
                        '\'' => '\'',
                        '"' => '"',
                        '`' => '`',
                        '?' => '?',
                        'x' | 'X' | 'u' | 'U' | '0'..='3' => escape(escaped, &mut chars)?,
                        _ => return Err(format!("unsupported string escape: \\{escaped}")),
                    });
                } else {
                    if ch == '\n' {
                        return Err("unterminated string".into());
                    }
                    value.push(ch);
                }
            }
            self.offset += end.ok_or("unterminated string")?;
            self.token = Token::String(value);
        } else if first == '('
            || first == ')'
            || first == ','
            || first == '['
            || first == ']'
            || first == '#'
        {
            self.offset += 1;
            self.token = match first {
                '(' => Token::Left,
                ')' => Token::Right,
                '[' => Token::ListStart,
                ']' => Token::ListEnd,
                '#' => Token::Current,
                _ => Token::Comma,
            };
        } else {
            let op = [
                "==", "!=", "<=", ">=", "&&", "||", "+", "-", "*", "/", "%", "<", ">", "!",
            ]
            .into_iter()
            .find(|op| rest.starts_with(op))
            .ok_or_else(|| format!("unsupported token: {first}"))?;
            self.offset += op.len();
            self.token = Token::Op(op.to_owned());
        }
        Ok(())
    }

    fn expression(&mut self, minimum: u8) -> Result<Node, String> {
        let left = match std::mem::replace(&mut self.token, Token::End) {
            Token::Integer(value) => {
                self.advance()?;
                Node::Int(value)
            }
            Token::Float(value) => {
                self.advance()?;
                Node::Float(value)
            }
            Token::String(value) => {
                self.advance()?;
                Node::String(value)
            }
            Token::Ident(name) if name == "true" || name == "false" => {
                self.advance()?;
                Node::Bool(name == "true")
            }
            Token::Ident(name) if name == "not" => {
                self.advance()?;
                self.unary(Unary::Not)?
            }
            Token::Ident(name) => {
                self.advance()?;
                if self.token != Token::Left {
                    let kind = self
                        .variables
                        .iter()
                        .find_map(|(key, kind)| (*key == name).then_some(Kind::from(*kind)))
                        .ok_or_else(|| format!("unknown identifier: {name}"))?;
                    return self.binary_tail(Node::Variable(name, kind), minimum);
                }
                self.advance()?;
                if name == "any" {
                    let list = self.expression(0)?;
                    let Node::List(items) = list else {
                        return Err("any requires a literal list".into());
                    };
                    if items.iter().any(|item| {
                        items
                            .first()
                            .is_some_and(|first| first.kind() != item.kind())
                    }) {
                        return Err("any requires a uniform list".into());
                    }
                    if self.token != Token::Comma {
                        return Err("any requires a predicate".into());
                    }
                    self.advance()?;
                    let previous = self.current;
                    self.current = items.first().map(Node::kind);
                    let predicate = self.expression(0)?;
                    self.current = previous;
                    if predicate.kind() != Kind::Bool {
                        return Err("any predicate must be boolean".into());
                    }
                    if self.token != Token::Right {
                        return Err("missing closing parenthesis in any".into());
                    }
                    self.advance()?;
                    return self.binary_tail(Node::Any(items, Box::new(predicate)), minimum);
                }
                let mut args = Vec::new();
                if self.token != Token::Right {
                    loop {
                        args.push(self.expression(0)?);
                        if self.token != Token::Comma {
                            break;
                        }
                        self.advance()?;
                    }
                }
                if self.token != Token::Right {
                    return Err(format!("missing closing parenthesis in {name}"));
                }
                self.advance()?;
                let kind = match name.as_str() {
                    "metadata" if args.len() == 1 && args[0].kind() == Kind::String => Kind::String,
                    "incidr"
                        if args.len() == 2 && args.iter().all(|arg| arg.kind() == Kind::String) =>
                    {
                        Kind::Bool
                    }
                    "group"
                        if args.len() == 1
                            && matches!(args[0].kind(), Kind::String | Kind::Int) =>
                    {
                        Kind::String
                    }
                    "int"
                        if args.len() == 1
                            && matches!(args[0].kind(), Kind::String | Kind::Int | Kind::Float) =>
                    {
                        Kind::Int
                    }
                    "replace"
                        if (args.len() == 3 || args.len() == 4)
                            && args[..3].iter().all(|arg| arg.kind() == Kind::String)
                            && (args.len() == 3 || args[3].kind() == Kind::Int) =>
                    {
                        Kind::String
                    }
                    "type" | "name" | "class" | "proto" | "client_ip" | "port" | "server_ip"
                    | "server_port"
                        if args.is_empty() =>
                    {
                        Kind::String
                    }
                    "size" | "id" | "opcode" | "bufsize" if args.is_empty() => Kind::Int,
                    "do" if args.is_empty() => Kind::Bool,
                    _ => return Err(format!("unsupported function or arguments: {name}")),
                };
                Node::Call(name, args, kind)
            }
            Token::Op(op) if op == "!" || op == "-" => {
                self.advance()?;
                self.unary(if op == "!" { Unary::Not } else { Unary::Neg })?
            }
            Token::Left => {
                self.advance()?;
                let node = self.expression(0)?;
                if self.token != Token::Right {
                    return Err("missing closing parenthesis".into());
                }
                self.advance()?;
                node
            }
            Token::ListStart => {
                self.advance()?;
                let mut values = Vec::new();
                if self.token != Token::ListEnd {
                    loop {
                        values.push(self.expression(0)?);
                        if self.token != Token::Comma {
                            break;
                        }
                        self.advance()?;
                        if self.token == Token::ListEnd {
                            break;
                        }
                    }
                }
                if self.token != Token::ListEnd {
                    return Err("missing closing bracket".into());
                }
                self.advance()?;
                Node::List(values)
            }
            Token::Current => {
                let kind = self
                    .current
                    .ok_or("# is only valid in an any predicate with a typed list")?;
                self.advance()?;
                Node::Current(kind)
            }
            other => return Err(format!("unsupported expression: {other:?}")),
        };
        self.binary_tail(left, minimum)
    }

    fn binary_tail(&mut self, mut left: Node, minimum: u8) -> Result<Node, String> {
        loop {
            let negated = matches!(&self.token, Token::Ident(name) if name == "not");
            if negated {
                if minimum > 3 {
                    break;
                }
                self.advance()?;
            }
            let Some((op, precedence)) = self.binary() else {
                if negated {
                    return Err("not must precede a membership or string operator".into());
                }
                break;
            };
            if negated
                && !matches!(
                    op,
                    Binary::In
                        | Binary::Contains
                        | Binary::StartsWith
                        | Binary::EndsWith
                        | Binary::Matches
                )
            {
                return Err("not must precede a membership or string operator".into());
            }
            if precedence < minimum {
                break;
            }
            self.advance()?;
            let right = self.expression(precedence + 1)?;
            if matches!(op, Binary::Matches) {
                if left.kind() != Kind::String {
                    return Err("matches requires a string".into());
                }
                let Node::String(pattern) = right else {
                    return Err("matches requires a literal pattern".into());
                };
                left = Node::Matches(
                    Box::new(left),
                    Box::new(crate::regex_match::Regex::new(&pattern)?),
                );
                if negated {
                    left = Node::Unary(Unary::Not, Box::new(left));
                }
                continue;
            }
            let kind = match op {
                Binary::And | Binary::Or
                    if left.kind() == Kind::Bool && right.kind() == Kind::Bool =>
                {
                    Kind::Bool
                }
                Binary::Add | Binary::Sub | Binary::Mul | Binary::Rem
                    if left.kind() == Kind::Int && right.kind() == Kind::Int =>
                {
                    Kind::Int
                }
                Binary::Add | Binary::Sub | Binary::Mul | Binary::Div
                    if left.kind().numeric() && right.kind().numeric() =>
                {
                    Kind::Float
                }
                Binary::Add if left.kind() == Kind::String && right.kind() == Kind::String => {
                    Kind::String
                }
                Binary::In if matches!(&right, Node::List(values) if values.iter().all(|value| value.kind() == left.kind() || (value.kind().numeric() && left.kind().numeric()))) => {
                    Kind::Bool
                }
                Binary::Contains | Binary::StartsWith | Binary::EndsWith
                    if left.kind() == Kind::String && right.kind() == Kind::String =>
                {
                    Kind::Bool
                }
                Binary::Eq | Binary::Ne | Binary::Lt | Binary::Le | Binary::Gt | Binary::Ge
                    if (left.kind() == right.kind() && left.kind() != Kind::List)
                        || (left.kind().numeric() && right.kind().numeric()) =>
                {
                    Kind::Bool
                }
                _ => return Err("incompatible expression operands".into()),
            };
            left = Node::Binary(op, Box::new(left), Box::new(right), kind);
            if negated {
                left = Node::Unary(Unary::Not, Box::new(left));
            }
        }
        Ok(left)
    }

    fn unary(&mut self, op: Unary) -> Result<Node, String> {
        let node = self.expression(6)?;
        if !match op {
            Unary::Not => node.kind() == Kind::Bool,
            Unary::Neg => node.kind().numeric(),
        } {
            return Err("incompatible unary operand".into());
        }
        Ok(Node::Unary(op, Box::new(node)))
    }

    fn binary(&self) -> Option<(Binary, u8)> {
        let value = match &self.token {
            Token::Op(op) | Token::Ident(op) => op.as_str(),
            _ => return None,
        };
        Some(match value {
            "||" | "or" => (Binary::Or, 1),
            "&&" | "and" => (Binary::And, 2),
            "==" => (Binary::Eq, 3),
            "!=" => (Binary::Ne, 3),
            "<" => (Binary::Lt, 3),
            "<=" => (Binary::Le, 3),
            ">" => (Binary::Gt, 3),
            ">=" => (Binary::Ge, 3),
            "in" => (Binary::In, 3),
            "contains" => (Binary::Contains, 3),
            "startsWith" => (Binary::StartsWith, 3),
            "endsWith" => (Binary::EndsWith, 3),
            "matches" => (Binary::Matches, 3),
            "+" => (Binary::Add, 4),
            "-" => (Binary::Sub, 4),
            "*" => (Binary::Mul, 5),
            "/" => (Binary::Div, 5),
            "%" => (Binary::Rem, 5),
            _ => return None,
        })
    }
}

fn escape(first: char, chars: &mut std::str::CharIndices<'_>) -> Result<char, String> {
    let octal = matches!(first, '0'..='3');
    let mut value = if octal {
        first.to_digit(8).unwrap_or_default()
    } else {
        0
    };
    let mut length = match first {
        'x' | 'X' => 2,
        'u' => 4,
        'U' => 8,
        _ => 2,
    };
    let braced = first == 'u' && chars.clone().next().is_some_and(|(_, ch)| ch == '{');
    if braced {
        chars.next();
        length = 0;
    }
    if braced {
        for (_, ch) in chars.by_ref() {
            if ch == '}' {
                if length == 0 {
                    return Err("empty Unicode escape".into());
                }
                return char::from_u32(value)
                    .or_else(|| (value <= 0x10ffff).then_some('\u{fffd}'))
                    .ok_or_else(|| "invalid Unicode escape".into());
            }
            if length == 6 {
                return Err("Unicode escape too long".into());
            }
            value = value * 16 + ch.to_digit(16).ok_or("invalid Unicode escape")?;
            length += 1;
        }
        return Err("unterminated Unicode escape".into());
    }
    for _ in 0..length {
        let (_, ch) = chars.next().ok_or("incomplete string escape")?;
        value = value * if octal { 8 } else { 16 }
            + ch.to_digit(if octal { 8 } else { 16 })
                .ok_or("invalid string escape")?;
    }
    char::from_u32(value)
        .or_else(|| (value <= 0x10ffff).then_some('\u{fffd}'))
        .ok_or_else(|| "invalid Unicode escape".into())
}
