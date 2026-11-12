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
        } else if first == '(' || first == ')' || first == ',' {
            self.offset += 1;
            self.token = match first {
                '(' => Token::Left,
                ')' => Token::Right,
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
            other => return Err(format!("unsupported expression: {other:?}")),
        };
        while let Some((op, precedence)) = self.binary() {
            if precedence < minimum {
                break;
            }
            self.advance()?;
            let right = self.expression(precedence + 1)?;
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
                Binary::Eq | Binary::Ne | Binary::Lt | Binary::Le | Binary::Gt | Binary::Ge
                    if left.kind() == right.kind() =>
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
            "+" => (Binary::Add, 4),
            "-" => (Binary::Sub, 4),
            "*" => (Binary::Mul, 5),
            "/" => (Binary::Div, 5),
            "%" => (Binary::Rem, 5),
            _ => return None,
        })
    }
}
