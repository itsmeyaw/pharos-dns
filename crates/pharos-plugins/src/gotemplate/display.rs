use super::{Value, pipeline::QuestionSlice};
use std::fmt::{self, Write};

pub(super) fn matches(output: &mut impl Write, values: &[&str]) -> fmt::Result {
    output.write_char('[')?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.write_char(' ')?;
        }
        output.write_str(value)?;
    }
    output.write_char(']')
}

pub(super) fn map<'a>(
    output: &mut impl Write,
    values: impl Iterator<Item = (&'a str, Value<'a>)> + Clone,
) -> fmt::Result {
    output.write_str("map[")?;
    let mut last = None;
    // shortcut: sorted map printing scans quadratically; pre-sort keys at setup for large maps.
    while let Some((key, value)) = values
        .clone()
        .filter(|(key, _)| last.is_none_or(|last| *key > last))
        .min_by_key(|(key, _)| *key)
    {
        if last.is_some() {
            output.write_char(' ')?;
        }
        write!(output, "{key}:")?;
        value_string(output, value)?;
        last = Some(key);
    }
    output.write_char(']')
}

pub(super) fn value_string(output: &mut impl Write, value: Value<'_>) -> fmt::Result {
    match value {
        Value::Nil => output.write_str("<nil>"),
        Value::Bool(value) => write!(output, "{value}"),
        Value::Int(value) => write!(output, "{value}"),
        Value::Float(value) => super::float::write_float(output, value),
        Value::String(value) => output.write_str(value),
        Value::Function(_) => Err(fmt::Error),
    }
}

pub(super) fn questions(output: &mut impl Write, values: QuestionSlice<'_>) -> fmt::Result {
    output.write_char('[')?;
    for (index, question) in values
        .message
        .questions()
        .skip(values.start)
        .take(values.end - values.start)
        .enumerate()
    {
        if index != 0 {
            output.write_char(' ')?;
        }
        write!(
            output,
            "{{{} {} {}}}",
            question.name, question.qtype.0, question.qclass.0
        )?;
    }
    output.write_char(']')
}
