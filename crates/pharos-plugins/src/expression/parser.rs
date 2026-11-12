use super::{Binary, Kind, Node, Unary};

#[derive(Debug, PartialEq)]
enum Token {
    Integer(i64),
    String(String),
    Ident(String),
    Op(String),
    Left,
    Right,
    Comma,
    ListStart,
    ListEnd,
    End,
}

pub(super) fn parse(source: &str) -> Result<Node, String> {
    let mut parser = Parser {
        source,
        offset: 0,
        token: Token::End,
    };
    parser.advance()?;
    let node = parser.expression(0)?;
    if parser.token != Token::End {
        return Err(format!("unexpected token {:?}", parser.token));
    }
    Ok(node)
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    token: Token,
}

impl Parser<'_> {
    fn advance(&mut self) -> Result<(), String> {
        let rest = &self.source[self.offset..];
        self.offset += rest.len() - rest.trim_start().len();
        let rest = &self.source[self.offset..];
        let Some(first) = rest.chars().next() else {
            self.token = Token::End;
            return Ok(());
        };
        if first.is_ascii_digit() {
            let len = rest.bytes().take_while(u8::is_ascii_digit).count();
            self.token = Token::Integer(rest[..len].parse().map_err(|_| "invalid integer")?);
            self.offset += len;
        } else if first.is_ascii_alphabetic() || first == '_' {
            let len = rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            self.token = Token::Ident(rest[..len].to_owned());
            self.offset += len;
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
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' => '\\',
                        '\'' => '\'',
                        '"' => '"',
                        _ => return Err(format!("unsupported string escape: \\{escaped}")),
                    });
                } else {
                    value.push(ch);
                }
            }
            self.offset += end.ok_or("unterminated string")?;
            self.token = Token::String(value);
        } else if first == '(' || first == ')' || first == ',' || first == '[' || first == ']' {
            self.offset += 1;
            self.token = match first {
                '(' => Token::Left,
                ')' => Token::Right,
                '[' => Token::ListStart,
                ']' => Token::ListEnd,
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
        let mut left = match std::mem::replace(&mut self.token, Token::End) {
            Token::Integer(value) => {
                self.advance()?;
                Node::Int(value)
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
                    return Err(format!("unknown identifier: {name}"));
                }
                self.advance()?;
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
            other => return Err(format!("unsupported expression: {other:?}")),
        };
        while let Some((op, precedence)) = self.binary() {
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
                left = Node::Matches(Box::new(left), crate::regex_match::Regex::new(&pattern)?);
                continue;
            }
            let kind = match op {
                Binary::And | Binary::Or
                    if left.kind() == Kind::Bool && right.kind() == Kind::Bool =>
                {
                    Kind::Bool
                }
                Binary::Add | Binary::Sub | Binary::Mul | Binary::Div | Binary::Rem
                    if left.kind() == Kind::Int && right.kind() == Kind::Int =>
                {
                    Kind::Int
                }
                Binary::In if matches!(&right, Node::List(values) if values.iter().all(|value| value.kind() == left.kind())) => {
                    Kind::Bool
                }
                Binary::Contains | Binary::StartsWith | Binary::EndsWith
                    if left.kind() == Kind::String && right.kind() == Kind::String =>
                {
                    Kind::Bool
                }
                Binary::Eq | Binary::Ne | Binary::Lt | Binary::Le | Binary::Gt | Binary::Ge
                    if left.kind() == right.kind() && left.kind() != Kind::List =>
                {
                    Kind::Bool
                }
                _ => return Err("incompatible expression operands".into()),
            };
            left = Node::Binary(op, Box::new(left), Box::new(right), kind);
        }
        Ok(left)
    }

    fn unary(&mut self, op: Unary) -> Result<Node, String> {
        let node = self.expression(6)?;
        if node.kind()
            != match op {
                Unary::Not => Kind::Bool,
                Unary::Neg => Kind::Int,
            }
        {
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
