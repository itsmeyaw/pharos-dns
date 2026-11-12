//! Compiled Go-template expressions used by the template Plugin.

use crate::expression::Value;
use pharos_server::Metadata;
use std::fmt::{self, Write};

/// Borrowed template values for a Query.
pub struct Data<'a, 'm> {
    pub name: &'a str,
    pub zone: &'a str,
    pub class: &'a str,
    pub qtype: &'a str,
    pub remote: &'a str,
    pub regex: &'a str,
    pub matches: &'a [&'a str],
    pub groups: &'a [(&'a str, &'a str)],
    pub variables: &'a [(&'a str, Value<'a>)],
    pub metadata: &'a Metadata<'m>,
}

impl<'a, 'm> Data<'a, 'm> {
    /// Construct data with empty optional template fields.
    pub fn new(name: &'a str, metadata: &'a Metadata<'m>) -> Self {
        Self {
            name,
            metadata,
            zone: "",
            class: "",
            qtype: "",
            remote: "",
            regex: "",
            matches: &[],
            groups: &[],
            variables: &[],
        }
    }
}

enum Field {
    Literal(String),
    Name,
    Zone,
    Class,
    Type,
    Remote,
    Regex,
    Group(String),
    Variable(String),
    Match(usize),
    Metadata(String),
}

enum Part {
    Text(String),
    Field(Field),
    ParseInt(Field, u32, u32),
    If(Field, Vec<Part>, Vec<Part>),
}

/// A template parsed at setup time.
pub struct Template(Vec<Part>);

impl Template {
    /// Compile the supported template actions.
    pub fn compile(mut source: &str) -> Result<Self, String> {
        let (parts, marker) = parse_parts(&mut source, 0)?;
        if marker.is_some() {
            return Err("unexpected template else or end".into());
        }
        Ok(Self(parts))
    }

    /// Append the rendered template to a caller-provided buffer.
    pub fn render(&self, data: &Data<'_, '_>, output: &mut String) -> fmt::Result {
        render_parts(&self.0, data, output)
    }
}

fn render_parts(parts: &[Part], data: &Data<'_, '_>, output: &mut String) -> fmt::Result {
    for part in parts {
        match part {
            Part::Text(text) => output.write_str(text)?,
            Part::Field(Field::Variable(name)) => match data
                .variables
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(value))
            {
                Some(Value::Nil) | None => output.write_str("<no value>")?,
                Some(Value::Bool(value)) => write!(output, "{value}")?,
                Some(Value::Int(value)) => write!(output, "{value}")?,
                Some(Value::Float(value)) => write!(output, "{value}")?,
                Some(Value::String(value)) => output.write_str(value)?,
            },
            Part::Field(field) => output.write_str(field.value(data)?)?,
            Part::ParseInt(field, base, bits) => {
                if (*base != 0 && !(2..=36).contains(base)) || *bits > 64 {
                    return Err(fmt::Error);
                }
                let value = parse_uint(field.value(data)?, *base)?;
                if *bits != 0 && *bits < 64 && value >= (1u64 << bits) {
                    return Err(fmt::Error);
                }
                write!(output, "{value}")?;
            }
            Part::If(condition, yes, no) => {
                render_parts(if condition.truthy(data)? { yes } else { no }, data, output)?
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Marker {
    Else,
    End,
}

fn parse_parts(source: &mut &str, depth: usize) -> Result<(Vec<Part>, Option<Marker>), String> {
    // shortcut: 256 nested actions bound recursive rendering; use an iterative renderer to lift this limit.
    if depth >= 256 {
        return Err("template nesting exceeds 256 levels".into());
    }
    let mut parts = Vec::new();
    while let Some(start) = source.find("{{") {
        let mut text = &source[..start];
        let mut action_source = &source[start + 2..];
        if action_source.starts_with('-')
            && action_source
                .as_bytes()
                .get(1)
                .is_some_and(|byte| is_space(*byte))
        {
            text = text.trim_end_matches(|ch: char| ch.is_ascii() && is_space(ch as u8));
            action_source = &action_source[1..];
        }
        parts.push(Part::Text(text.to_owned()));
        *source = action_source;
        let end = source.find("}}").ok_or("unclosed template action")?;
        let mut raw = &source[..end];
        let trim_right = raw.ends_with('-')
            && raw
                .as_bytes()
                .get(raw.len().saturating_sub(2))
                .is_some_and(|byte| is_space(*byte));
        if trim_right {
            raw = &raw[..raw.len() - 1];
        }
        let action = raw.trim();
        *source = &source[end + 2..];
        if trim_right {
            *source = source.trim_start_matches(|ch: char| ch.is_ascii() && is_space(ch as u8));
        }
        match action {
            "else" => return Ok((parts, Some(Marker::Else))),
            "end" => return Ok((parts, Some(Marker::End))),
            _ => {}
        }
        let part = if let Some(condition) = action.strip_prefix("if ") {
            let condition = parse_field(condition.trim())?;
            let (yes, marker) = parse_parts(source, depth + 1)?;
            let no = if marker == Some(Marker::Else) {
                let (no, marker) = parse_parts(source, depth + 1)?;
                if marker != Some(Marker::End) {
                    return Err("if is missing end".into());
                }
                no
            } else if marker == Some(Marker::End) {
                Vec::new()
            } else {
                return Err("if is missing end".into());
            };
            Part::If(condition, yes, no)
        } else if let Some(args) = action.strip_prefix("parseInt ") {
            let mut args = args.split_whitespace();
            let field = parse_field(args.next().ok_or("parseInt needs three arguments")?)?;
            let base = args
                .next()
                .ok_or("parseInt needs a base")?
                .parse::<u32>()
                .map_err(|_| "invalid parseInt base")?;
            let bits = args
                .next()
                .ok_or("parseInt needs a bit size")?
                .parse::<u32>()
                .map_err(|_| "invalid parseInt bit size")?;
            if args.next().is_some() {
                return Err("parseInt has too many arguments".into());
            }
            Part::ParseInt(field, base, bits)
        } else {
            Part::Field(parse_field(action)?)
        };
        parts.push(part);
    }
    parts.push(Part::Text((*source).to_owned()));
    *source = "";
    Ok((parts, None))
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn parse_field(action: &str) -> Result<Field, String> {
    match action {
        ".Name" => Ok(Field::Name),
        ".Zone" => Ok(Field::Zone),
        ".Class" => Ok(Field::Class),
        ".Type" => Ok(Field::Type),
        ".Remote" => Ok(Field::Remote),
        ".Regex" => Ok(Field::Regex),
        _ => {
            if let Some(literal) = action.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                if literal.contains(['\\', '"', '\n', '\r']) {
                    return Err("unsupported quoted-string escape".into());
                }
                Ok(Field::Literal(literal.to_owned()))
            } else if let Some(name) = action
                .strip_prefix(".Group.")
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
            {
                Ok(Field::Group(name.to_owned()))
            } else if let Some(name) = action
                .strip_prefix(".Var.")
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
            {
                Ok(Field::Variable(name.to_owned()))
            } else if let Some(index) = action.strip_prefix("index .Match ") {
                Ok(Field::Match(
                    index.trim().parse().map_err(|_| "invalid .Match index")?,
                ))
            } else if let Some(label) = action.strip_prefix(".Meta ") {
                let label = label
                    .trim()
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .ok_or("unsupported .Meta argument")?;
                if label.contains(['\\', '"', '\n', '\r']) {
                    return Err("unsupported quoted-string escape".into());
                }
                Ok(Field::Metadata(label.to_owned()))
            } else {
                Err(format!("unsupported template action: {action}"))
            }
        }
    }
}

impl Field {
    fn truthy(&self, data: &Data<'_, '_>) -> Result<bool, fmt::Error> {
        match self {
            Self::Variable(name) => Ok(
                match data
                    .variables
                    .iter()
                    .find_map(|(key, value)| (*key == name).then_some(value))
                {
                    Some(Value::Bool(value)) => *value,
                    Some(Value::Int(value)) => *value != 0,
                    Some(Value::Float(value)) => *value != 0.0,
                    Some(Value::String(value)) => !value.is_empty(),
                    Some(Value::Nil) | None => false,
                },
            ),
            Self::Group(name) => Ok(data
                .groups
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(!value.is_empty()))
                .unwrap_or(false)),
            _ => Ok(!self.value(data)?.is_empty()),
        }
    }
    fn value<'a>(&'a self, data: &'a Data<'_, '_>) -> Result<&'a str, fmt::Error> {
        match self {
            Self::Literal(value) => Ok(value),
            Self::Name => Ok(data.name),
            Self::Zone => Ok(data.zone),
            Self::Class => Ok(data.class),
            Self::Type => Ok(data.qtype),
            Self::Remote => Ok(data.remote),
            Self::Regex => Ok(data.regex),
            Self::Group(name) => Ok(data
                .groups
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(*value))
                .unwrap_or("<no value>")),
            Self::Variable(name) => match data
                .variables
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(value))
            {
                Some(Value::String(value)) => Ok(value),
                None => Ok("<no value>"),
                _ => Err(fmt::Error),
            },
            Self::Match(index) => data.matches.get(*index).copied().ok_or(fmt::Error),
            Self::Metadata(label) => Ok(data.metadata.get(label).unwrap_or("")),
        }
    }
}

fn parse_uint(value: &str, base: u32) -> Result<u64, fmt::Error> {
    let (digits, radix, allow_underscore) = if base == 0 {
        if let Some(digits) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            (digits, 16, true)
        } else if let Some(digits) = value
            .strip_prefix("0b")
            .or_else(|| value.strip_prefix("0B"))
        {
            (digits, 2, true)
        } else if let Some(digits) = value
            .strip_prefix("0o")
            .or_else(|| value.strip_prefix("0O"))
        {
            (digits, 8, true)
        } else if value.len() > 1 && value.starts_with('0') {
            (value, 8, true)
        } else {
            (value, 10, true)
        }
    } else {
        (value, base, false)
    };
    let mut result = 0u64;
    let mut previous_digit = value.len() != digits.len();
    let mut seen_digit = false;
    for ch in digits.chars() {
        if ch == '_' && allow_underscore && previous_digit {
            previous_digit = false;
            continue;
        }
        let digit = ch.to_digit(radix).ok_or(fmt::Error)?;
        result = result
            .checked_mul(u64::from(radix))
            .and_then(|n| n.checked_add(u64::from(digit)))
            .ok_or(fmt::Error)?;
        previous_digit = true;
        seen_digit = true;
    }
    if !seen_digit || !previous_digit {
        return Err(fmt::Error);
    }
    Ok(result)
}
