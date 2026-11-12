//! Compiled Go-template expressions used by the template Plugin.

use crate::expression::Value;
use pharos_proto::{Message, NameRef, Question};
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
    pub message: Option<&'a Message<'a>>,
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
            message: None,
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
    Questions,
    CurrentQtype,
    CurrentQclass,
    Unknown,
    QuestionName,
    QueryScalar(QueryField),
    Name,
    Zone,
    Class,
    Type,
    Remote,
    Regex,
    Group(String),
    Variable(String),
    Local(String),
    LocalQuestion(String, QuestionMember),
    Match(usize),
    Metadata(String),
}

enum QueryField {
    Id,
    Opcode,
    Rcode,
    Flag(u16),
    QuestionType,
    QuestionClass,
}

#[derive(Clone, Copy)]
enum QuestionMember {
    Name,
    Qtype,
    Qclass,
}

impl QuestionMember {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "Name" => Some(Self::Name),
            "Qtype" => Some(Self::Qtype),
            "Qclass" => Some(Self::Qclass),
            _ => None,
        }
    }
    fn numeric(self, question: Question<'_>) -> Option<Value<'static>> {
        match self {
            Self::Name => None,
            Self::Qtype => Some(Value::Int(i64::from(question.qtype.0))),
            Self::Qclass => Some(Value::Int(i64::from(question.qclass.0))),
        }
    }
}

enum Part {
    Text(String),
    Field(Field),
    If(Condition, Vec<Part>, Vec<Part>),
    Range(pipeline::Pipeline, Vec<String>, Vec<Part>, Vec<Part>),
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
        let (parts, marker) = parse_parts(&mut source, 0, &[])?;
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
    Range {
        value: Value<'a>,
        key: Value<'a>,
        names: &'a [String],
        parent: &'a Dot<'a>,
    },
    Question {
        value: Question<'a>,
        key: Value<'a>,
        names: &'a [String],
        parent: &'a Dot<'a>,
    },
}

impl<'a> Dot<'a> {
    fn value(self) -> Option<Value<'a>> {
        match self {
            Self::Root | Self::Question { .. } => None,
            Self::Range { value, .. } => Some(value),
        }
    }
    fn local(self, name: &str) -> Option<Value<'a>> {
        match self {
            Self::Range {
                value,
                key,
                names,
                parent,
            } => {
                if names.len() == 1 && names[0] == name {
                    Some(value)
                } else if names.len() == 2 && names[0] == name {
                    Some(key)
                } else if names.len() == 2 && names[1] == name {
                    Some(value)
                } else {
                    parent.local(name)
                }
            }
            Self::Question {
                key, names, parent, ..
            } => {
                if names.len() == 2 && names[0] == name {
                    Some(key)
                } else if names.iter().any(|candidate| candidate == name) {
                    None
                } else {
                    parent.local(name)
                }
            }
            _ => None,
        }
    }

    fn local_question(self, name: &str) -> Option<Question<'a>> {
        match self {
            Self::Question {
                value,
                names,
                parent,
                ..
            } => {
                if names.len() == 1 && names[0] == name || names.len() == 2 && names[1] == name {
                    Some(value)
                } else if names.iter().any(|candidate| candidate == name) {
                    None
                } else {
                    parent.local_question(name)
                }
            }
            Self::Range { names, parent, .. } => {
                if names.iter().any(|candidate| candidate == name) {
                    None
                } else {
                    parent.local_question(name)
                }
            }
            Self::Root => None,
        }
    }
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
            Part::Range(pipeline, names, body, otherwise) => match pipeline.range(data, dot)? {
                pipeline::RangeValue::Empty => render_parts(otherwise, data, dot, output)?,
                pipeline::RangeValue::Integer(count) => {
                    if names.len() > 1 {
                        return Err(fmt::Error);
                    }
                    if count <= 0 {
                        render_parts(otherwise, data, dot, output)?;
                    }
                    for value in 0..count {
                        let nested = Dot::Range {
                            value: Value::Int(value),
                            key: Value::Nil,
                            names,
                            parent: &dot,
                        };
                        render_parts(body, data, nested, output)?;
                    }
                }
                pipeline::RangeValue::Matches(matches) => {
                    if matches.is_empty() {
                        render_parts(otherwise, data, dot, output)?;
                    }
                    for (index, value) in matches.iter().enumerate() {
                        let nested = Dot::Range {
                            value: Value::String(value),
                            key: Value::Int(index as i64),
                            names,
                            parent: &dot,
                        };
                        render_parts(body, data, nested, output)?;
                    }
                }
                pipeline::RangeValue::Groups(groups) => render_map(
                    groups
                        .iter()
                        .map(|(key, value)| (*key, Value::String(value))),
                    names,
                    body,
                    otherwise,
                    data,
                    dot,
                    output,
                )?,
                pipeline::RangeValue::Variables(variables) => render_map(
                    variables.iter().map(|(key, value)| (*key, *value)),
                    names,
                    body,
                    otherwise,
                    data,
                    dot,
                    output,
                )?,
                pipeline::RangeValue::Questions(message) => {
                    let mut any = false;
                    for (index, question) in message.questions().enumerate() {
                        any = true;
                        let nested = Dot::Question {
                            value: question,
                            key: Value::Int(index as i64),
                            names,
                            parent: &dot,
                        };
                        render_parts(body, data, nested, output)?;
                    }
                    if !any {
                        render_parts(otherwise, data, dot, output)?;
                    }
                }
            },
            Part::Pipeline(pipeline) => pipeline.write(data, dot, output)?,
        }
    }
    Ok(())
}

fn render_map<'a>(
    entries: impl Iterator<Item = (&'a str, Value<'a>)> + Clone,
    names: &[String],
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
        let nested = Dot::Range {
            value,
            key: Value::String(key),
            names,
            parent: &dot,
        };
        render_parts(body, data, nested, output)?;
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
        Some(Value::Function(_)) => Err(fmt::Error),
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
        Field::QuestionName if matches!(dot, Dot::Root) => {
            write!(output, "{}", question_name(data)?)
        }
        Field::Name if matches!(dot, Dot::Question { .. }) => {
            let Dot::Question { value, .. } = dot else {
                unreachable!()
            };
            write!(output, "{}", value.name)
        }
        Field::CurrentQtype | Field::CurrentQclass if matches!(dot, Dot::Question { .. }) => {
            write_value(field.scalar(data, dot)?, output)
        }
        Field::QueryScalar(field) if matches!(dot, Dot::Root) => {
            write_value(Some(field.value(data)?), output)
        }
        Field::Dot => match dot {
            Dot::Question { value, .. } => write!(
                output,
                "{{{} {} {}}}",
                value.name, value.qtype.0, value.qclass.0
            ),
            _ => write_value(dot.value().ok_or(fmt::Error).map(Some)?, output),
        },
        Field::Local(name) => {
            if let Some(question) = dot.local_question(name) {
                write!(
                    output,
                    "{{{} {} {}}}",
                    question.name, question.qtype.0, question.qclass.0
                )
            } else {
                write_value(dot.local(name), output)
            }
        }
        Field::LocalQuestion(name, member) => {
            let question = dot.local_question(name).ok_or(fmt::Error)?;
            match member {
                QuestionMember::Name => write!(output, "{}", question.name),
                member => write_value(member.numeric(question), output),
            }
        }
        Field::Variable(name) if matches!(dot, Dot::Root) => write_value(
            data.variables
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(*value)),
            output,
        ),
        _ => output.write_str(field.value(data, dot)?),
    }
}

enum Marker {
    Else,
    ElseIf(String),
    End,
}

fn parse_parts(
    source: &mut &str,
    depth: usize,
    scope: &[String],
) -> Result<(Vec<Part>, Option<Marker>), String> {
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
        if let Some(condition) = action.strip_prefix("else if ") {
            validate_variables(condition, scope)?;
            return Ok((parts, Some(Marker::ElseIf(condition.trim().to_owned()))));
        }
        let range = action.starts_with("range ");
        let part = if let Some(condition) = action
            .strip_prefix("if ")
            .or_else(|| action.strip_prefix("range "))
        {
            let condition = condition.trim();
            let (field, names) = if range {
                let (names, expression) = match condition.split_once(":=") {
                    Some((names, expression)) => {
                        let names = names
                            .split(',')
                            .map(str::trim)
                            .map(|name| {
                                let name = name
                                    .strip_prefix('$')
                                    .filter(|name| {
                                        !name.is_empty()
                                            && name
                                                .chars()
                                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                                    })
                                    .ok_or("invalid range variable")?;
                                Ok(name.to_owned())
                            })
                            .collect::<Result<Vec<_>, String>>()?;
                        if names.is_empty() || names.len() > 2 {
                            return Err("range needs one or two variables".into());
                        }
                        (names, expression.trim())
                    }
                    None => (Vec::new(), condition),
                };
                validate_variables(expression, scope)?;
                (Some(pipeline::Pipeline::compile(expression)?), names)
            } else {
                validate_variables(condition, scope)?;
                (None, Vec::new())
            };
            let mut branch_scope = scope.to_vec();
            branch_scope.extend(names.iter().cloned());
            let (yes, no) = parse_branches(source, depth + 1, &branch_scope)?;
            if let Some(pipeline) = field {
                Part::Range(pipeline, names, yes, no)
            } else {
                Part::If(Condition::parse(condition)?, yes, no)
            }
        } else {
            validate_variables(action, scope)?;
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

fn parse_branches(
    source: &mut &str,
    depth: usize,
    scope: &[String],
) -> Result<(Vec<Part>, Vec<Part>), String> {
    let (yes, marker) = parse_parts(source, depth, scope)?;
    let no = match marker {
        Some(Marker::End) => Vec::new(),
        Some(Marker::Else) => {
            let (no, marker) = parse_parts(source, depth, scope)?;
            if !matches!(marker, Some(Marker::End)) {
                return Err("control action is missing end".into());
            }
            no
        }
        Some(Marker::ElseIf(condition)) => {
            let condition = Condition::parse(&condition)?;
            let (inner_yes, inner_no) = parse_branches(source, depth + 1, scope)?;
            vec![Part::If(condition, inner_yes, inner_no)]
        }
        None => return Err("control action is missing end".into()),
    };
    Ok((yes, no))
}

fn validate_variables(source: &str, scope: &[String]) -> Result<(), String> {
    let bytes = source.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
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
        } else if byte == b'$' {
            let start = index + 1;
            let mut end = start;
            while bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                end += 1;
            }
            if end > start && !scope.iter().any(|name| name == &source[start..end]) {
                return Err(format!(
                    "undefined template variable: ${}",
                    &source[start..end]
                ));
            }
            index = end.saturating_sub(1);
        }
        index += 1;
    }
    Ok(())
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
    if let Some((name, field)) = action
        .strip_prefix('$')
        .and_then(|action| action.split_once('.'))
        && !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Ok(match QuestionMember::parse(field) {
            Some(member) => Field::LocalQuestion(name.to_owned(), member),
            None => Field::Unknown,
        });
    }
    if let Some(name) = action.strip_prefix('$').filter(|name| {
        !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    }) {
        return Ok(Field::Local(name.to_owned()));
    }
    let header = action
        .strip_prefix(".Message.MsgHdr.")
        .or_else(|| action.strip_prefix(".Message."));
    if let Some(header) = header {
        let value = match header {
            "Id" => Some(QueryField::Id),
            "Opcode" => Some(QueryField::Opcode),
            "Rcode" => Some(QueryField::Rcode),
            "Response" => Some(QueryField::Flag(0x8000)),
            "Authoritative" => Some(QueryField::Flag(0x0400)),
            "Truncated" => Some(QueryField::Flag(0x0200)),
            "RecursionDesired" => Some(QueryField::Flag(0x0100)),
            "RecursionAvailable" => Some(QueryField::Flag(0x0080)),
            "Zero" => Some(QueryField::Flag(0x0040)),
            "AuthenticatedData" => Some(QueryField::Flag(0x0020)),
            "CheckingDisabled" => Some(QueryField::Flag(0x0010)),
            _ => None,
        };
        if let Some(value) = value {
            return Ok(Field::QueryScalar(value));
        }
    }
    match action {
        "." => Ok(Field::Dot),
        ".Match" => Ok(Field::Matches),
        ".Group" => Ok(Field::Groups),
        ".Var" => Ok(Field::Variables),
        ".Message.Question" => Ok(Field::Questions),
        ".Qtype" => Ok(Field::CurrentQtype),
        ".Qclass" => Ok(Field::CurrentQclass),
        ".Question.Name" => Ok(Field::QuestionName),
        ".Question.Qtype" => Ok(Field::QueryScalar(QueryField::QuestionType)),
        ".Question.Qclass" => Ok(Field::QueryScalar(QueryField::QuestionClass)),
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
            Self::QueryScalar(field) if matches!(dot, Dot::Root) => Ok(Some(field.value(data)?)),
            Self::CurrentQtype if matches!(dot, Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot else {
                    unreachable!()
                };
                Ok(Some(Value::Int(i64::from(value.qtype.0))))
            }
            Self::CurrentQclass if matches!(dot, Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot else {
                    unreachable!()
                };
                Ok(Some(Value::Int(i64::from(value.qclass.0))))
            }
            Self::Dot => dot.value().map(Some).ok_or(fmt::Error),
            Self::Local(name) => Ok(dot.local(name)),
            Self::LocalQuestion(name, member) => member
                .numeric(dot.local_question(name).ok_or(fmt::Error)?)
                .map(Some)
                .ok_or(fmt::Error),
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
            Self::Dot => Ok(dot.value().is_none_or(truth_value)),
            Self::Local(name) => {
                Ok(dot.local_question(name).is_some() || dot.local(name).is_some_and(truth_value))
            }
            Self::LocalQuestion(name, member) => {
                let question = dot.local_question(name).ok_or(fmt::Error)?;
                Ok(member.numeric(question).is_none_or(truth_value))
            }
            Self::Matches if matches!(dot, Dot::Root) => Ok(!data.matches.is_empty()),
            Self::Groups if matches!(dot, Dot::Root) => Ok(!data.groups.is_empty()),
            Self::Variables if matches!(dot, Dot::Root) => Ok(!data.variables.is_empty()),
            Self::Questions if matches!(dot, Dot::Root) => {
                Ok(data.message.ok_or(fmt::Error)?.questions().next().is_some())
            }
            Self::Name if matches!(dot, Dot::Question { .. }) => Ok(true),
            Self::CurrentQtype | Self::CurrentQclass if matches!(dot, Dot::Question { .. }) => {
                Ok(self.scalar(data, dot)?.is_some_and(truth_value))
            }
            Self::QueryScalar(field) if matches!(dot, Dot::Root) => {
                Ok(match field.value(data)? {
                    Value::Bool(value) => value,
                    Value::Int(value) => value != 0,
                    _ => return Err(fmt::Error),
                })
            }
            Self::QuestionName if matches!(dot, Dot::Root) => {
                question_name(data)?;
                Ok(true)
            }
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
                    Some(Value::Function(_)) => true,
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
            Self::Dot => match dot.value() {
                Some(Value::String(value)) => Ok(value),
                _ => Err(fmt::Error),
            },
            Self::Local(name) => match dot.local(name) {
                Some(Value::String(value)) => Ok(value),
                _ => Err(fmt::Error),
            },
            Self::Literal(value) => Ok(value),
            _ if !matches!(dot, Dot::Root) => Err(fmt::Error),
            Self::Matches
            | Self::Groups
            | Self::Variables
            | Self::Questions
            | Self::CurrentQtype
            | Self::CurrentQclass
            | Self::LocalQuestion(_, _)
            | Self::Unknown
            | Self::QuestionName
            | Self::QueryScalar(_) => Err(fmt::Error),
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
            Self::Metadata(label) => Ok(if data.metadata.enabled() {
                data.metadata.get(label).unwrap_or("")
            } else {
                ""
            }),
        }
    }
}

fn truth_value(value: Value<'_>) -> bool {
    match value {
        Value::Nil => false,
        Value::Bool(value) => value,
        Value::Int(value) => value != 0,
        Value::Float(value) => value != 0.0,
        Value::String(value) => !value.is_empty(),
        Value::Function(_) => true,
    }
}

fn question_name<'a>(data: &'a Data<'_, '_>) -> Result<NameRef<'a>, fmt::Error> {
    Ok(data
        .message
        .ok_or(fmt::Error)?
        .questions()
        .next()
        .ok_or(fmt::Error)?
        .name)
}

impl QueryField {
    fn value(&self, data: &Data<'_, '_>) -> Result<Value<'static>, fmt::Error> {
        let message = data.message.ok_or(fmt::Error)?;
        // RFC 1035 §4.1.1–4.1.2: header flags and first Question carry these values.
        Ok(match self {
            Self::Id => Value::Int(i64::from(message.id())),
            Self::Opcode => Value::Int(i64::from(message.opcode().0)),
            Self::Rcode => Value::Int(i64::from(message.rcode().0)),
            Self::Flag(mask) => Value::Bool(message.flags() & mask != 0),
            Self::QuestionType => Value::Int(i64::from(
                message.questions().next().ok_or(fmt::Error)?.qtype.0,
            )),
            Self::QuestionClass => Value::Int(i64::from(
                message.questions().next().ok_or(fmt::Error)?.qclass.0,
            )),
        })
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
