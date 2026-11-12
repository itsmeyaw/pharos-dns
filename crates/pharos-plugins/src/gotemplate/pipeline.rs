use super::{Data, Dot, Field, Value, compare, parse_field, parse_uint};
use std::fmt::{self, Write};

enum Atom {
    Field(Field),
    Int(i64),
    Bool(bool),
    Nil,
}
enum Function {
    Eq,
    Len,
    Not,
    ParseInt,
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
    Collection(usize),
}

impl Pipeline {
    pub(super) fn compile(source: &str) -> Result<Self, String> {
        let mut commands = Vec::new();
        for (index, stage) in split(source, '|')?.into_iter().enumerate() {
            let words = split_words(stage)?;
            let first = *words.first().ok_or("empty pipeline command")?;
            let function = match first {
                "eq" => Some(Function::Eq),
                "len" => Some(Function::Len),
                "not" => Some(Function::Not),
                "parseInt" => Some(Function::ParseInt),
                _ => None,
            };
            let command = if let Some(function) = function {
                let args = words[1..]
                    .iter()
                    .map(|word| atom(word))
                    .collect::<Result<Vec<_>, _>>()?;
                let count = args.len() + usize::from(index != 0);
                let valid = match function {
                    Function::Eq => count >= 2,
                    Function::Len | Function::Not => count == 1,
                    Function::ParseInt => count == 3,
                };
                if !valid {
                    return Err(format!("invalid argument count for {first}"));
                }
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
                    match function {
                        Function::Eq => {
                            let first = get(0)?;
                            let mut same = false;
                            for index in 1..count {
                                same |= first.equal(get(index)?)?;
                            }
                            ResultValue::Scalar(Some(Value::Bool(same)))
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
            ResultValue::Collection(_) => Err(fmt::Error),
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
            Self::Field(field @ (Field::Matches | Field::Groups | Field::Variables)) => {
                Ok(ResultValue::Collection(field.length(data, dot)?))
            }
            Self::Field(Field::Root(field))
                if matches!(
                    field.as_ref(),
                    Field::Matches | Field::Groups | Field::Variables
                ) =>
            {
                Ok(ResultValue::Collection(field.length(data, Dot::Root)?))
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
            Self::Collection(value) => value != 0,
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
            Self::Collection(value) => Ok(value),
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
}

fn atom(word: &str) -> Result<Atom, String> {
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
    let mut quote = false;
    let mut escape = false;
    let mut start = 0;
    for (index, ch) in source.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote && ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            quote = !quote;
            continue;
        }
        if !quote && ch == separator {
            result.push(source[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    if quote {
        return Err("unterminated quoted string".into());
    }
    result.push(source[start..].trim());
    Ok(result)
}

fn split_words(source: &str) -> Result<Vec<&str>, String> {
    let mut result = Vec::new();
    let mut quote = false;
    let mut escape = false;
    let mut start = None;
    for (index, ch) in source.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote && ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            quote = !quote;
        }
        if !quote && ch.is_ascii_whitespace() {
            if let Some(begin) = start.take() {
                result.push(&source[begin..index]);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if quote {
        return Err("unterminated quoted string".into());
    }
    if let Some(begin) = start {
        result.push(&source[begin..]);
    }
    Ok(result)
}
