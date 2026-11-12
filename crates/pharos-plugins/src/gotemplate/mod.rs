//! Compiled Go-template expressions used by the template Plugin.

use crate::expression::Value;
use pharos_server::Metadata;
use std::fmt::{self, Write};

mod pipeline;
mod quote;

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
    Dot,
    Root(Box<Field>),
    Matches,
    Groups,
    Variables,
    Unknown,
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
    If(Condition, Vec<Part>, Vec<Part>),
    Range(Field, Vec<Part>, Vec<Part>),
    Pipeline(pipeline::Pipeline),
}

enum Condition {
    Field(Field),
    Pipeline(pipeline::Pipeline),
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
        render_parts(&self.0, data, Dot::Root, output)
    }
}

#[derive(Clone, Copy)]
enum Dot<'a> {
    Root,
    Value(Value<'a>),
}

fn render_parts(
    parts: &[Part],
    data: &Data<'_, '_>,
    dot: Dot<'_>,
    output: &mut String,
) -> fmt::Result {
    for part in parts {
        match part {
            Part::Text(text) => output.write_str(text)?,
            Part::Field(field) => write_field(field, data, dot, output)?,
            Part::If(condition, yes, no) => render_parts(
                if condition.truthy(data, dot)? {
                    yes
                } else {
                    no
                },
                data,
                dot,
                output,
            )?,
            Part::Range(field, body, otherwise) => {
                let field = match field {
                    Field::Root(field) => field.as_ref(),
                    field if matches!(dot, Dot::Root) => field,
                    _ => return Err(fmt::Error),
                };
                match field {
                    Field::Matches => {
                        if data.matches.is_empty() {
                            render_parts(otherwise, data, dot, output)?;
                        }
                        for value in data.matches {
                            render_parts(body, data, Dot::Value(Value::String(value)), output)?;
                        }
                    }
                    Field::Groups => render_map(
                        data.groups
                            .iter()
                            .map(|(key, value)| (*key, Value::String(value))),
                        body,
                        otherwise,
                        data,
                        dot,
                        output,
                    )?,
                    Field::Variables => render_map(
                        data.variables.iter().map(|(key, value)| (*key, *value)),
                        body,
                        otherwise,
                        data,
                        dot,
                        output,
                    )?,
                    _ => return Err(fmt::Error),
                }
            }
            Part::Pipeline(pipeline) => pipeline.write(data, dot, output)?,
        }
    }
    Ok(())
}

fn render_map<'a>(
    entries: impl Iterator<Item = (&'a str, Value<'a>)> + Clone,
    body: &[Part],
    otherwise: &[Part],
    data: &Data<'_, '_>,
    dot: Dot<'_>,
    output: &mut String,
) -> fmt::Result {
    // shortcut: map iteration scans quadratically; pre-sort keys at setup if large maps are needed.
    let mut last = None;
    let mut any = false;
    while let Some((key, value)) = entries
        .clone()
        .filter(|(key, _)| last.is_none_or(|previous| *key > previous))
        .min_by_key(|(key, _)| *key)
    {
        any = true;
        render_parts(body, data, Dot::Value(value), output)?;
        last = Some(key);
    }
    if !any {
        render_parts(otherwise, data, dot, output)?;
    }
    Ok(())
}

impl Condition {
    fn parse(source: &str) -> Result<Self, String> {
        match parse_field(source) {
            Ok(field) => Ok(Self::Field(field)),
            Err(_) => Ok(Self::Pipeline(pipeline::Pipeline::compile(source)?)),
        }
    }
    fn truthy(&self, data: &Data<'_, '_>, dot: Dot<'_>) -> Result<bool, fmt::Error> {
        match self {
            Self::Field(field) => field.truthy(data, dot),
            Self::Pipeline(pipeline) => pipeline.truthy(data, dot),
        }
    }
}

fn write_value(value: Option<Value<'_>>, output: &mut String) -> fmt::Result {
    match value {
        Some(Value::Nil) | None => output.write_str("<no value>"),
        Some(Value::Bool(value)) => write!(output, "{value}"),
        Some(Value::Int(value)) => write!(output, "{value}"),
        Some(Value::Float(value)) => write!(output, "{value}"),
        Some(Value::String(value)) => output.write_str(value),
    }
}

fn write_field(
    field: &Field,
    data: &Data<'_, '_>,
    dot: Dot<'_>,
    output: &mut String,
) -> fmt::Result {
    match field {
        Field::Root(field) => write_field(field, data, Dot::Root, output),
        Field::Dot => match dot {
            Dot::Value(value) => write_value(Some(value), output),
            Dot::Root => Err(fmt::Error),
        },
        Field::Variable(name) if matches!(dot, Dot::Root) => write_value(
            data.variables
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(*value)),
            output,
        ),
        _ => output.write_str(field.value(data, dot)?),
    }
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
        let end = action_end(source).ok_or("unclosed template action")?;
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
        let range = action.starts_with("range ");
        let part = if let Some(condition) = action
            .strip_prefix("if ")
            .or_else(|| action.strip_prefix("range "))
        {
            let condition = condition.trim();
            let field = if range {
                Some(parse_field(condition)?)
            } else {
                None
            };
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
            if let Some(field) = field {
                Part::Range(field, yes, no)
            } else {
                Part::If(Condition::parse(condition)?, yes, no)
            }
        } else {
            match parse_field(action) {
                Ok(field) => Part::Field(field),
                Err(_) => Part::Pipeline(pipeline::Pipeline::compile(action)?),
            }
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

fn action_end(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' && active != b'`' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
        } else if matches!(byte, b'"' | b'\'' | b'`') {
            quote = Some(byte);
        } else if byte == b'}' && bytes.get(offset + 1) == Some(&b'}') {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn parse_field(action: &str) -> Result<Field, String> {
    if let Some(field) = action.strip_prefix("$.") {
        return Ok(Field::Root(Box::new(parse_field(&format!(".{field}"))?)));
    }
    match action {
        "." => Ok(Field::Dot),
        ".Match" => Ok(Field::Matches),
        ".Group" => Ok(Field::Groups),
        ".Var" => Ok(Field::Variables),
        ".Name" => Ok(Field::Name),
        ".Zone" => Ok(Field::Zone),
        ".Class" => Ok(Field::Class),
        ".Type" => Ok(Field::Type),
        ".Remote" => Ok(Field::Remote),
        ".Regex" => Ok(Field::Regex),
        _ => {
            if action.starts_with('"') || action.starts_with('`') {
                Ok(Field::Literal(quote::unquote(action)?))
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
                Ok(Field::Metadata(quote::unquote(label.trim())?))
            } else if action.strip_prefix('.').is_some_and(|path| {
                path.split('.').all(|name| {
                    !name.is_empty() && name.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
                })
            }) {
                Ok(Field::Unknown)
            } else {
                Err(format!("unsupported template action: {action}"))
            }
        }
    }
}

impl Field {
    fn scalar<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
    ) -> Result<Option<Value<'a>>, fmt::Error> {
        match self {
            Self::Root(field) => field.scalar(data, Dot::Root),
            Self::Dot => match dot {
                Dot::Value(value) => Ok(Some(value)),
                Dot::Root => Err(fmt::Error),
            },
            Self::Variable(name) if matches!(dot, Dot::Root) => Ok(data
                .variables
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(*value))),
            Self::Group(name) if matches!(dot, Dot::Root) => Ok(data
                .groups
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(Value::String(value)))),
            _ => Ok(Some(Value::String(self.value(data, dot)?))),
        }
    }

    fn truthy(&self, data: &Data<'_, '_>, dot: Dot<'_>) -> Result<bool, fmt::Error> {
        match self {
            Self::Root(field) => field.truthy(data, Dot::Root),
            Self::Dot => Ok(match dot {
                Dot::Root => true,
                Dot::Value(Value::Nil) => false,
                Dot::Value(Value::Bool(value)) => value,
                Dot::Value(Value::Int(value)) => value != 0,
                Dot::Value(Value::Float(value)) => value != 0.0,
                Dot::Value(Value::String(value)) => !value.is_empty(),
            }),
            Self::Matches if matches!(dot, Dot::Root) => Ok(!data.matches.is_empty()),
            Self::Groups if matches!(dot, Dot::Root) => Ok(!data.groups.is_empty()),
            Self::Variables if matches!(dot, Dot::Root) => Ok(!data.variables.is_empty()),
            Self::Literal(_) => Ok(!self.value(data, dot)?.is_empty()),
            _ if !matches!(dot, Dot::Root) => Err(fmt::Error),
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
            _ => Ok(!self.value(data, dot)?.is_empty()),
        }
    }
    fn value<'a>(&'a self, data: &'a Data<'_, '_>, dot: Dot<'a>) -> Result<&'a str, fmt::Error> {
        match self {
            Self::Root(field) => field.value(data, Dot::Root),
            Self::Dot => match dot {
                Dot::Value(Value::String(value)) => Ok(value),
                _ => Err(fmt::Error),
            },
            Self::Literal(value) => Ok(value),
            _ if !matches!(dot, Dot::Root) => Err(fmt::Error),
            Self::Matches | Self::Groups | Self::Variables | Self::Unknown => Err(fmt::Error),
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

fn compare(a: Option<Value<'_>>, b: Option<Value<'_>>) -> Result<bool, fmt::Error> {
    match (a, b) {
        (None | Some(Value::Nil), None | Some(Value::Nil)) => Ok(true),
        (None | Some(Value::Nil), _) | (_, None | Some(Value::Nil)) => Ok(false),
        (Some(Value::Bool(a)), Some(Value::Bool(b))) => Ok(a == b),
        (Some(Value::Int(a)), Some(Value::Int(b))) => Ok(a == b),
        (Some(Value::Float(a)), Some(Value::Float(b))) => Ok(a == b),
        (Some(Value::String(a)), Some(Value::String(b))) => Ok(a == b),
        _ => Err(fmt::Error),
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
