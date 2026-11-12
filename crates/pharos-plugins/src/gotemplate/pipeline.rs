use super::{Data, Dot, Field, Value, compare, parse_field, parse_uint};
use std::fmt::{self, Write};

enum Atom {
    Field(Field),
    Nested(Box<Pipeline>),
    Int(i64),
    Bool(bool),
    Nil,
}
enum Function {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Len,
    Not,
    ParseInt,
    Index,
    Slice,
}
enum Command {
    Atom(Atom),
    Call(Function, Vec<Atom>),
}

pub(super) struct Pipeline(Vec<Command>);

#[derive(Clone, Copy)]
enum ResultValue<'a> {
    Scalar(Option<Value<'a>>),
    Uint(u64),
    Matches(&'a [&'a str]),
    Groups(&'a [(&'a str, &'a str)]),
    Variables(&'a [(&'a str, Value<'a>)]),
}

impl Pipeline {
    pub(super) fn compile(source: &str) -> Result<Self, String> {
        let mut commands = Vec::new();
        for (index, stage) in split(source, '|')?.into_iter().enumerate() {
            let words = split_words(stage)?;
            let first = *words.first().ok_or("empty pipeline command")?;
            let function = match first {
                "eq" => Some(Function::Eq),
                "ne" => Some(Function::Ne),
                "lt" => Some(Function::Lt),
                "le" => Some(Function::Le),
                "gt" => Some(Function::Gt),
                "ge" => Some(Function::Ge),
                "and" => Some(Function::And),
                "or" => Some(Function::Or),
                "len" => Some(Function::Len),
                "not" => Some(Function::Not),
                "parseInt" => Some(Function::ParseInt),
                "index" => Some(Function::Index),
                "slice" => Some(Function::Slice),
                _ => None,
            };
            let command = if let Some(function) = function {
                let args = words[1..]
                    .iter()
                    .map(|word| atom(word))
                    .collect::<Result<Vec<_>, _>>()?;
                Command::Call(function, args)
            } else {
                if index != 0 || words.len() != 1 {
                    return Err(format!("unsupported pipeline command: {stage}"));
                }
                Command::Atom(atom(first)?)
            };
            commands.push(command);
        }
        Ok(Self(commands))
    }

    fn evaluate<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        let mut value = None;
        for command in &self.0 {
            value = Some(match command {
                Command::Atom(atom) => atom.value(data, dot)?,
                Command::Call(function, args) => {
                    let count = args.len() + usize::from(value.is_some());
                    let get = |index: usize| -> Result<ResultValue<'a>, fmt::Error> {
                        if let Some(atom) = args.get(index) {
                            atom.value(data, dot)
                        } else {
                            value.ok_or(fmt::Error)
                        }
                    };
                    let valid = match function {
                        Function::Eq => count >= 2,
                        Function::And | Function::Or => count >= 1,
                        Function::Ne
                        | Function::Lt
                        | Function::Le
                        | Function::Gt
                        | Function::Ge => count == 2,
                        Function::Len | Function::Not => count == 1,
                        Function::ParseInt => count == 3,
                        Function::Index => count >= 2,
                        Function::Slice => (2..=4).contains(&count),
                    };
                    if !valid {
                        return Err(fmt::Error);
                    }
                    match function {
                        Function::Eq => {
                            let first = get(0)?;
                            let mut same = false;
                            for index in 1..count {
                                same |= first.equal(get(index)?)?;
                            }
                            ResultValue::Scalar(Some(Value::Bool(same)))
                        }
                        Function::Ne => {
                            ResultValue::Scalar(Some(Value::Bool(!get(0)?.equal(get(1)?)?)))
                        }
                        Function::Lt | Function::Le | Function::Gt | Function::Ge => {
                            let ordering = get(0)?.order(get(1)?)?;
                            let result = match function {
                                Function::Lt => ordering.is_some_and(|v| v.is_lt()),
                                Function::Le => ordering.is_some_and(|v| v.is_le()),
                                Function::Gt => ordering.is_some_and(|v| v.is_gt()),
                                Function::Ge => ordering.is_some_and(|v| v.is_ge()),
                                _ => unreachable!(),
                            };
                            ResultValue::Scalar(Some(Value::Bool(result)))
                        }
                        Function::And | Function::Or => {
                            let mut result = get(0)?;
                            for index in 1..count {
                                if matches!(function, Function::And) && !result.truthy()
                                    || matches!(function, Function::Or) && result.truthy()
                                {
                                    break;
                                }
                                result = get(index)?;
                            }
                            result
                        }
                        Function::Len => {
                            ResultValue::Scalar(Some(Value::Int(get(0)?.length()? as i64)))
                        }
                        Function::Not => ResultValue::Scalar(Some(Value::Bool(!get(0)?.truthy()))),
                        Function::ParseInt => {
                            let input = get(0)?.text()?;
                            let base = get(1)?.integer()?;
                            let bits = get(2)?.integer()?;
                            let (base, bits) = (
                                u32::try_from(base).map_err(|_| fmt::Error)?,
                                u32::try_from(bits).map_err(|_| fmt::Error)?,
                            );
                            if (base != 0 && !(2..=36).contains(&base)) || bits > 64 {
                                return Err(fmt::Error);
                            }
                            let parsed = parse_uint(input, base)?;
                            if bits != 0 && bits < 64 && parsed >= 1u64 << bits {
                                return Err(fmt::Error);
                            }
                            ResultValue::Uint(parsed)
                        }
                        Function::Index => {
                            let mut indexed = get(0)?;
                            for index in 1..count {
                                indexed = indexed.index(get(index)?)?;
                            }
                            indexed
                        }
                        Function::Slice => {
                            let input = get(0)?;
                            let len = input.length()?;
                            let low =
                                usize::try_from(get(1)?.integer()?).map_err(|_| fmt::Error)?;
                            let high = if count >= 3 {
                                usize::try_from(get(2)?.integer()?).map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            let max = if count == 4 {
                                usize::try_from(get(3)?.integer()?).map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            input.slice(low, high, max, count == 4)?
                        }
                    }
                }
            });
        }
        value.ok_or(fmt::Error)
    }

    pub(super) fn write(
        &self,
        data: &Data<'_, '_>,
        dot: Dot<'_>,
        output: &mut String,
    ) -> fmt::Result {
        match self.evaluate(data, dot)? {
            ResultValue::Scalar(value) => super::write_value(value, output),
            ResultValue::Uint(value) => write!(output, "{value}"),
            ResultValue::Matches(_) | ResultValue::Groups(_) | ResultValue::Variables(_) => {
                Err(fmt::Error)
            }
        }
    }

    pub(super) fn truthy(&self, data: &Data<'_, '_>, dot: Dot<'_>) -> Result<bool, fmt::Error> {
        Ok(self.evaluate(data, dot)?.truthy())
    }
}

impl Atom {
    fn value<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        match self {
            Self::Int(value) => Ok(ResultValue::Scalar(Some(Value::Int(*value)))),
            Self::Bool(value) => Ok(ResultValue::Scalar(Some(Value::Bool(*value)))),
            Self::Nil => Ok(ResultValue::Scalar(Some(Value::Nil))),
            Self::Nested(pipeline) => pipeline.evaluate(data, dot),
            Self::Field(Field::Matches) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Matches(data.matches))
            }
            Self::Field(Field::Groups) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Groups(data.groups))
            }
            Self::Field(Field::Variables) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Variables(data.variables))
            }
            Self::Field(Field::Root(field))
                if matches!(
                    field.as_ref(),
                    Field::Matches | Field::Groups | Field::Variables
                ) =>
            {
                match field.as_ref() {
                    Field::Matches => Ok(ResultValue::Matches(data.matches)),
                    Field::Groups => Ok(ResultValue::Groups(data.groups)),
                    Field::Variables => Ok(ResultValue::Variables(data.variables)),
                    _ => unreachable!(),
                }
            }
            Self::Field(field) => Ok(ResultValue::Scalar(field.scalar(data, dot)?)),
        }
    }
}

impl<'a> ResultValue<'a> {
    fn truthy(self) -> bool {
        match self {
            Self::Scalar(None | Some(Value::Nil)) => false,
            Self::Scalar(Some(Value::Bool(value))) => value,
            Self::Scalar(Some(Value::Int(value))) => value != 0,
            Self::Scalar(Some(Value::Float(value))) => value != 0.0,
            Self::Scalar(Some(Value::String(value))) => !value.is_empty(),
            Self::Uint(value) => value != 0,
            Self::Matches(value) => !value.is_empty(),
            Self::Groups(value) => !value.is_empty(),
            Self::Variables(value) => !value.is_empty(),
        }
    }
    fn integer(self) -> Result<i64, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::Int(value))) => Ok(value),
            Self::Uint(value) => i64::try_from(value).map_err(|_| fmt::Error),
            _ => Err(fmt::Error),
        }
    }
    fn text(self) -> Result<&'a str, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::String(value))) => Ok(value),
            _ => Err(fmt::Error),
        }
    }
    fn length(self) -> Result<usize, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::String(value))) => Ok(value.len()),
            Self::Matches(value) => Ok(value.len()),
            Self::Groups(value) => Ok(value.len()),
            Self::Variables(value) => Ok(value.len()),
            _ => Err(fmt::Error),
        }
    }
    fn index(self, key: Self) -> Result<Self, fmt::Error> {
        match self {
            Self::Matches(values) => Ok(Self::Scalar(Some(Value::String(
                values
                    .get(usize::try_from(key.integer()?).map_err(|_| fmt::Error)?)
                    .copied()
                    .ok_or(fmt::Error)?,
            )))),
            Self::Groups(values) => Ok(Self::Scalar(Some(Value::String(
                values
                    .iter()
                    .find_map(|(name, value)| (*name == key.text().ok()?).then_some(*value))
                    .unwrap_or(""),
            )))),
            Self::Variables(values) => {
                Ok(Self::Scalar(values.iter().find_map(|(name, value)| {
                    (*name == key.text().ok()?).then_some(*value)
                })))
            }
            Self::Scalar(Some(Value::String(value))) => Ok(Self::Uint(u64::from(
                *value
                    .as_bytes()
                    .get(usize::try_from(key.integer()?).map_err(|_| fmt::Error)?)
                    .ok_or(fmt::Error)?,
            ))),
            _ => Err(fmt::Error),
        }
    }
    fn slice(
        self,
        low: usize,
        high: usize,
        max: usize,
        three_index: bool,
    ) -> Result<Self, fmt::Error> {
        if low > high || high > max {
            return Err(fmt::Error);
        }
        match self {
            Self::Matches(values) => {
                if max > values.len() {
                    return Err(fmt::Error);
                }
                Ok(Self::Matches(values.get(low..high).ok_or(fmt::Error)?))
            }
            Self::Scalar(Some(Value::String(value))) if !three_index => Ok(Self::Scalar(Some(
                Value::String(value.get(low..high).ok_or(fmt::Error)?),
            ))),
            _ => Err(fmt::Error),
        }
    }
    fn equal(self, other: Self) -> Result<bool, fmt::Error> {
        match (self, other) {
            (Self::Scalar(a), Self::Scalar(b)) => compare(a, b),
            (Self::Uint(a), Self::Uint(b)) => Ok(a == b),
            (Self::Uint(a), Self::Scalar(Some(Value::Int(b))))
            | (Self::Scalar(Some(Value::Int(b))), Self::Uint(a)) => {
                Ok(u64::try_from(b).is_ok_and(|b| a == b))
            }
            _ => Err(fmt::Error),
        }
    }
    fn order(self, other: Self) -> Result<Option<std::cmp::Ordering>, fmt::Error> {
        match (self, other) {
            (Self::Scalar(Some(Value::Int(a))), Self::Scalar(Some(Value::Int(b)))) => {
                Ok(Some(a.cmp(&b)))
            }
            (Self::Scalar(Some(Value::Float(a))), Self::Scalar(Some(Value::Float(b)))) => {
                Ok(a.partial_cmp(&b))
            }
            (Self::Scalar(Some(Value::String(a))), Self::Scalar(Some(Value::String(b)))) => {
                Ok(Some(a.cmp(b)))
            }
            (Self::Uint(a), Self::Uint(b)) => Ok(Some(a.cmp(&b))),
            (Self::Uint(a), Self::Scalar(Some(Value::Int(b)))) => Ok(Some(if b < 0 {
                std::cmp::Ordering::Greater
            } else {
                a.cmp(&(b as u64))
            })),
            (Self::Scalar(Some(Value::Int(a))), Self::Uint(b)) => Ok(Some(if a < 0 {
                std::cmp::Ordering::Less
            } else {
                (a as u64).cmp(&b)
            })),
            _ => Err(fmt::Error),
        }
    }
}

fn atom(word: &str) -> Result<Atom, String> {
    if let Some(inner) = word
        .strip_prefix('(')
        .and_then(|word| word.strip_suffix(')'))
    {
        return Ok(Atom::Nested(Box::new(Pipeline::compile(inner)?)));
    }
    if word.starts_with('\'') {
        let decoded = super::quote::unquote(word)?;
        let mut chars = decoded.chars();
        let value = chars.next().ok_or("empty character literal")?;
        if chars.next().is_some() {
            return Err("character literal has multiple characters".into());
        }
        return Ok(Atom::Int(i64::from(u32::from(value))));
    }
    match word {
        "true" => Ok(Atom::Bool(true)),
        "false" => Ok(Atom::Bool(false)),
        "nil" => Ok(Atom::Nil),
        _ => {
            if let Ok(value) = word.parse::<i64>() {
                Ok(Atom::Int(value))
            } else {
                Ok(Atom::Field(parse_field(word)?))
            }
        }
    }
}

fn split(source: &str, separator: char) -> Result<Vec<&str>, String> {
    let mut result = Vec::new();
    let mut quote: Option<char> = None;
    let mut escape = false;
    let mut start = 0;
    let mut depth = 0usize;
    for (index, ch) in source.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote.is_some_and(|active| active != '`') && ch == '\\' {
            escape = true;
            continue;
        }
        if quote == Some(ch) {
            quote = None;
            continue;
        }
        if quote.is_none() && matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        // shortcut: cap nested pipelines at 255 levels; use iterative parsing to lift the stack limit.
        if quote.is_none() && ch == '(' {
            depth += 1;
            if depth >= 256 {
                return Err("pipeline nesting exceeds 255 levels".into());
            }
        }
        if quote.is_none() && ch == ')' {
            depth = depth.checked_sub(1).ok_or("unmatched parenthesis")?;
        }
        if quote.is_none() && depth == 0 && ch == separator {
            result.push(source[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string".into());
    }
    if depth != 0 {
        return Err("unclosed parenthesis".into());
    }
    result.push(source[start..].trim());
    Ok(result)
}

fn split_words(source: &str) -> Result<Vec<&str>, String> {
    let mut result = Vec::new();
    let mut quote: Option<char> = None;
    let mut escape = false;
    let mut start = None;
    let mut depth = 0usize;
    for (index, ch) in source.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote.is_some_and(|active| active != '`') && ch == '\\' {
            escape = true;
            continue;
        }
        let was_quoted = quote.is_some();
        if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
        }
        if !was_quoted && quote.is_none() && ch == '(' {
            depth += 1;
        }
        if !was_quoted && quote.is_none() && ch == ')' {
            depth = depth.checked_sub(1).ok_or("unmatched parenthesis")?;
        }
        if !was_quoted && quote.is_none() && depth == 0 && ch.is_ascii_whitespace() {
            if let Some(begin) = start.take() {
                result.push(&source[begin..index]);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string".into());
    }
    if depth != 0 {
        return Err("unclosed parenthesis".into());
    }
    if let Some(begin) = start {
        result.push(&source[begin..]);
    }
    Ok(result)
}
