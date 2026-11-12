use super::{Data, Dot, Field, Value, compare, parse_field, parse_uint};
use std::fmt::{self, Write};

enum Atom {
    Field(Field),
    Nested(Box<Pipeline>),
    Select(Box<Atom>, super::QuestionMember),
    Int(i64),
    Float(f64),
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
    Print,
    Println,
    Printf,
    Html,
    Js(Box<crate::regex_match::Regex>),
    UrlQuery,
    Meta(bool),
}
enum Command {
    Atom(Atom),
    Call(Function, Vec<Atom>),
}

pub(super) struct Pipeline(Vec<Command>);

pub(super) enum RangeValue<'a> {
    Empty,
    Integer(i64),
    Matches(&'a [&'a str]),
    Groups(&'a [(&'a str, &'a str)]),
    Variables(&'a [(&'a str, Value<'a>)]),
    Questions(&'a pharos_proto::Message<'a>),
}

#[derive(Clone, Copy)]
enum ResultValue<'a> {
    Scalar(Option<Value<'a>>),
    Uint(u64),
    Matches(&'a [&'a str]),
    Groups(&'a [(&'a str, &'a str)]),
    Variables(&'a [(&'a str, Value<'a>)]),
    Questions(&'a pharos_proto::Message<'a>),
    Question(pharos_proto::Question<'a>),
    Stored(usize, usize),
}

struct Scratch<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl Write for Scratch<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
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
                "print" => Some(Function::Print),
                "println" => Some(Function::Println),
                "printf" => Some(Function::Printf),
                "html" => Some(Function::Html),
                "js" => Some(Function::Js(Box::new(crate::regex_match::Regex::new(
                    r"^[\p{L}\p{M}\p{N}\p{P}\p{S}]$",
                )?))),
                "urlquery" => Some(Function::UrlQuery),
                ".Meta" => Some(Function::Meta(false)),
                "$.Meta" => Some(Function::Meta(true)),
                _ => None,
            };
            let command = if let Some(function) = function {
                let args = words[1..]
                    .iter()
                    .map(|word| atom(word))
                    .collect::<Result<Vec<_>, _>>()?;
                // shortcut: up to 1,024 arguments fit the stack; use caller-provided value slots for larger calls.
                if args.len() + usize::from(index != 0) > 1024 {
                    return Err("too many template arguments".into());
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
        scratch: &mut Scratch<'_>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        let mut value = None;
        for command in &self.0 {
            value = Some(match command {
                Command::Atom(atom) => atom.value(data, dot, scratch)?,
                Command::Call(function, args) => {
                    let count = args.len() + usize::from(value.is_some());
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
                        Function::Print
                        | Function::Println
                        | Function::Html
                        | Function::Js(_)
                        | Function::UrlQuery => true,
                        Function::Printf => count >= 1,
                        Function::Meta(_) => count == 1,
                    };
                    if !valid {
                        return Err(fmt::Error);
                    }
                    match function {
                        Function::Eq => {
                            let first = argument(args, 0, value, data, dot, scratch)?;
                            let mut same = false;
                            for index in 1..count {
                                let other = argument(args, index, value, data, dot, scratch)?;
                                same |= first.equal(other, scratch)?;
                            }
                            ResultValue::Scalar(Some(Value::Bool(same)))
                        }
                        Function::Ne => {
                            let a = argument(args, 0, value, data, dot, scratch)?;
                            let b = argument(args, 1, value, data, dot, scratch)?;
                            ResultValue::Scalar(Some(Value::Bool(!a.equal(b, scratch)?)))
                        }
                        Function::Lt | Function::Le | Function::Gt | Function::Ge => {
                            let a = argument(args, 0, value, data, dot, scratch)?;
                            let b = argument(args, 1, value, data, dot, scratch)?;
                            let ordering = a.order(b, scratch)?;
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
                            let mut result = argument(args, 0, value, data, dot, scratch)?;
                            for index in 1..count {
                                if matches!(function, Function::And) && !result.truthy(scratch)
                                    || matches!(function, Function::Or) && result.truthy(scratch)
                                {
                                    break;
                                }
                                result = argument(args, index, value, data, dot, scratch)?;
                            }
                            result
                        }
                        Function::Len => {
                            let input = argument(args, 0, value, data, dot, scratch)?;
                            ResultValue::Scalar(Some(Value::Int(input.length(scratch)? as i64)))
                        }
                        Function::Not => {
                            let input = argument(args, 0, value, data, dot, scratch)?;
                            ResultValue::Scalar(Some(Value::Bool(!input.truthy(scratch))))
                        }
                        Function::ParseInt => {
                            let input = argument(args, 0, value, data, dot, scratch)?;
                            let base = argument(args, 1, value, data, dot, scratch)?.integer()?;
                            let bits = argument(args, 2, value, data, dot, scratch)?.integer()?;
                            let (base, bits) = (
                                u32::try_from(base).map_err(|_| fmt::Error)?,
                                u32::try_from(bits).map_err(|_| fmt::Error)?,
                            );
                            if (base != 0 && !(2..=36).contains(&base)) || bits > 64 {
                                return Err(fmt::Error);
                            }
                            let parsed = parse_uint(input.text(scratch)?, base)?;
                            if bits != 0 && bits < 64 && parsed >= 1u64 << bits {
                                return Err(fmt::Error);
                            }
                            ResultValue::Uint(parsed)
                        }
                        Function::Index => {
                            let mut indexed = argument(args, 0, value, data, dot, scratch)?;
                            for index in 1..count {
                                let key = argument(args, index, value, data, dot, scratch)?;
                                indexed = indexed.index(key, scratch)?;
                            }
                            indexed
                        }
                        Function::Meta(root) => {
                            if !root && !matches!(dot, Dot::Root) {
                                return Err(fmt::Error);
                            }
                            let label = argument(args, 0, value, data, dot, scratch)?;
                            let label = label.text(scratch)?;
                            let result = if data.metadata.enabled() {
                                data.metadata.get(label).unwrap_or("")
                            } else {
                                ""
                            };
                            ResultValue::Scalar(Some(Value::String(result)))
                        }
                        Function::Slice => {
                            let input = argument(args, 0, value, data, dot, scratch)?;
                            let len = input.length(scratch)?;
                            let low = usize::try_from(
                                argument(args, 1, value, data, dot, scratch)?.integer()?,
                            )
                            .map_err(|_| fmt::Error)?;
                            let high = if count >= 3 {
                                usize::try_from(
                                    argument(args, 2, value, data, dot, scratch)?.integer()?,
                                )
                                .map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            let max = if count == 4 {
                                usize::try_from(
                                    argument(args, 3, value, data, dot, scratch)?.integer()?,
                                )
                                .map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            input.slice(low, high, max, count == 4, scratch)?
                        }
                        Function::Print
                        | Function::Println
                        | Function::Printf
                        | Function::Html
                        | Function::Js(_)
                        | Function::UrlQuery => {
                            let mut values = [None; 1024];
                            for (index, slot) in values[..count].iter_mut().enumerate() {
                                *slot = Some(argument(args, index, value, data, dot, scratch)?);
                            }
                            let start = scratch.len;
                            if matches!(
                                function,
                                Function::Html | Function::Js(_) | Function::UrlQuery
                            ) {
                                format_values(&Function::Print, &values[..count], scratch)?;
                                let end = scratch.len;
                                escape_values(function, start, end, scratch)?;
                                ResultValue::Stored(end, scratch.len)
                            } else {
                                format_values(function, &values[..count], scratch)?;
                                ResultValue::Stored(start, scratch.len)
                            }
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
        // shortcut: intermediate pipeline strings are limited to 65,535 bytes; accept caller scratch to lift this limit.
        let mut bytes = [0; 65535];
        let mut scratch = Scratch {
            bytes: &mut bytes,
            len: 0,
        };
        match self.evaluate(data, dot, &mut scratch)? {
            ResultValue::Scalar(value) => super::write_value(value, output),
            ResultValue::Uint(value) => write!(output, "{value}"),
            ResultValue::Stored(start, end) => output.write_str(
                std::str::from_utf8(&scratch.bytes[start..end]).map_err(|_| fmt::Error)?,
            ),
            ResultValue::Question(question) => write!(
                output,
                "{{{} {} {}}}",
                question.name, question.qtype.0, question.qclass.0
            ),
            ResultValue::Matches(_)
            | ResultValue::Groups(_)
            | ResultValue::Variables(_)
            | ResultValue::Questions(_) => Err(fmt::Error),
        }
    }

    pub(super) fn truthy(&self, data: &Data<'_, '_>, dot: Dot<'_>) -> Result<bool, fmt::Error> {
        let mut bytes = [0; 65535];
        let mut scratch = Scratch {
            bytes: &mut bytes,
            len: 0,
        };
        Ok(self.evaluate(data, dot, &mut scratch)?.truthy(&scratch))
    }

    pub(super) fn range<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
    ) -> Result<RangeValue<'a>, fmt::Error> {
        let mut bytes = [0; 65535];
        let mut scratch = Scratch {
            bytes: &mut bytes,
            len: 0,
        };
        match self.evaluate(data, dot, &mut scratch)? {
            ResultValue::Scalar(None | Some(Value::Nil)) => Ok(RangeValue::Empty),
            ResultValue::Scalar(Some(Value::Int(value))) => Ok(RangeValue::Integer(value)),
            ResultValue::Uint(value) => Ok(RangeValue::Integer(
                i64::try_from(value).map_err(|_| fmt::Error)?,
            )),
            ResultValue::Matches(values) => Ok(RangeValue::Matches(values)),
            ResultValue::Groups(values) => Ok(RangeValue::Groups(values)),
            ResultValue::Variables(values) => Ok(RangeValue::Variables(values)),
            ResultValue::Questions(message) => Ok(RangeValue::Questions(message)),
            _ => Err(fmt::Error),
        }
    }
}

fn escape_values(
    function: &Function,
    start: usize,
    end: usize,
    scratch: &mut Scratch<'_>,
) -> fmt::Result {
    let mut offset = start;
    while offset < end {
        let ch = std::str::from_utf8(&scratch.bytes[offset..end])
            .map_err(|_| fmt::Error)?
            .chars()
            .next()
            .ok_or(fmt::Error)?;
        offset += ch.len_utf8();
        match function {
            Function::Html => match ch {
                '\0' => scratch.write_char('\u{fffd}')?,
                '"' => scratch.write_str("&#34;")?,
                '\'' => scratch.write_str("&#39;")?,
                '&' => scratch.write_str("&amp;")?,
                '<' => scratch.write_str("&lt;")?,
                '>' => scratch.write_str("&gt;")?,
                _ => scratch.write_char(ch)?,
            },
            Function::Js(printable) => match ch {
                '\\' => scratch.write_str("\\\\")?,
                '\'' => scratch.write_str("\\'")?,
                '"' => scratch.write_str("\\\"")?,
                '<' => scratch.write_str("\\u003C")?,
                '>' => scratch.write_str("\\u003E")?,
                '&' => scratch.write_str("\\u0026")?,
                '=' => scratch.write_str("\\u003D")?,
                ch if (ch as u32) < 32
                    || (ch as u32 >= 128 && !printable.is_match(ch.encode_utf8(&mut [0; 4]))) =>
                {
                    write!(scratch, "\\u{:04X}", ch as u32)?
                }
                _ => scratch.write_char(ch)?,
            },
            Function::UrlQuery => {
                let mut bytes = [0; 4];
                for byte in ch.encode_utf8(&mut bytes).bytes() {
                    match byte {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                            scratch.write_char(char::from(byte))?
                        }
                        b' ' => scratch.write_char('+')?,
                        _ => write!(scratch, "%{byte:02X}")?,
                    }
                }
            }
            _ => return Err(fmt::Error),
        }
    }
    Ok(())
}

impl Atom {
    fn value<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
        scratch: &mut Scratch<'_>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        match self {
            Self::Int(value) => Ok(ResultValue::Scalar(Some(Value::Int(*value)))),
            Self::Float(value) => Ok(ResultValue::Scalar(Some(Value::Float(*value)))),
            Self::Bool(value) => Ok(ResultValue::Scalar(Some(Value::Bool(*value)))),
            Self::Nil => Ok(ResultValue::Scalar(Some(Value::Nil))),
            Self::Nested(pipeline) => pipeline.evaluate(data, dot, scratch),
            Self::Field(Field::Dot) if matches!(dot, Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot else {
                    unreachable!()
                };
                Ok(ResultValue::Question(value))
            }
            Self::Select(atom, member) => {
                let ResultValue::Question(question) = atom.value(data, dot, scratch)? else {
                    return Err(fmt::Error);
                };
                question_member(*member, question, scratch)
            }
            Self::Field(Field::Local(name)) if dot.local_question(name).is_some() => Ok(
                ResultValue::Question(dot.local_question(name).ok_or(fmt::Error)?),
            ),
            Self::Field(Field::LocalQuestion(name, member)) => question_member(
                *member,
                dot.local_question(name).ok_or(fmt::Error)?,
                scratch,
            ),
            Self::Field(Field::Name) if matches!(dot, Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot else {
                    unreachable!()
                };
                let start = scratch.len;
                write!(scratch, "{}", value.name)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::QuestionName) if matches!(dot, Dot::Root) => {
                let start = scratch.len;
                write!(scratch, "{}", super::question_name(data)?)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::Root(field)) if matches!(field.as_ref(), Field::QuestionName) => {
                let start = scratch.len;
                write!(scratch, "{}", super::question_name(data)?)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::Matches) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Matches(data.matches))
            }
            Self::Field(Field::Groups) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Groups(data.groups))
            }
            Self::Field(Field::Variables) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Variables(data.variables))
            }
            Self::Field(Field::Questions) if matches!(dot, Dot::Root) => {
                Ok(ResultValue::Questions(data.message.ok_or(fmt::Error)?))
            }
            Self::Field(Field::Root(field))
                if matches!(
                    field.as_ref(),
                    Field::Matches | Field::Groups | Field::Variables | Field::Questions
                ) =>
            {
                match field.as_ref() {
                    Field::Matches => Ok(ResultValue::Matches(data.matches)),
                    Field::Groups => Ok(ResultValue::Groups(data.groups)),
                    Field::Variables => Ok(ResultValue::Variables(data.variables)),
                    Field::Questions => Ok(ResultValue::Questions(data.message.ok_or(fmt::Error)?)),
                    _ => unreachable!(),
                }
            }
            Self::Field(field) => Ok(ResultValue::Scalar(field.scalar(data, dot)?)),
        }
    }
}

fn question_member<'a>(
    member: super::QuestionMember,
    question: pharos_proto::Question<'a>,
    scratch: &mut Scratch<'_>,
) -> Result<ResultValue<'a>, fmt::Error> {
    match member {
        super::QuestionMember::Name => {
            let start = scratch.len;
            write!(scratch, "{}", question.name)?;
            Ok(ResultValue::Stored(start, scratch.len))
        }
        member => Ok(ResultValue::Scalar(member.numeric(question))),
    }
}

fn argument<'a>(
    args: &'a [Atom],
    index: usize,
    previous: Option<ResultValue<'a>>,
    data: &'a Data<'_, '_>,
    dot: Dot<'a>,
    scratch: &mut Scratch<'_>,
) -> Result<ResultValue<'a>, fmt::Error> {
    if let Some(atom) = args.get(index) {
        atom.value(data, dot, scratch)
    } else {
        previous.ok_or(fmt::Error)
    }
}

fn format_values(
    function: &Function,
    values: &[Option<ResultValue<'_>>],
    scratch: &mut Scratch<'_>,
) -> fmt::Result {
    if matches!(function, Function::Printf) {
        let format = values[0].ok_or(fmt::Error)?;
        let mut cursor = 0;
        let mut argument = 1;
        while cursor < format.text(scratch)?.len() {
            let ch = format.text(scratch)?[cursor..]
                .chars()
                .next()
                .ok_or(fmt::Error)?;
            cursor += ch.len_utf8();
            if ch != '%' {
                scratch.write_char(ch)?;
                continue;
            }
            let mut verb = format.text(scratch)?[cursor..]
                .chars()
                .next()
                .ok_or(fmt::Error)?;
            cursor += verb.len_utf8();
            if verb == '%' {
                scratch.write_char('%')?;
                continue;
            }
            let zero = verb == '0';
            let mut width = 0usize;
            while verb.is_ascii_digit() {
                width = width
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(verb.to_digit(10)? as usize))
                    .ok_or(fmt::Error)?;
                if width > 65535 {
                    return Err(fmt::Error);
                }
                verb = format.text(scratch)?[cursor..]
                    .chars()
                    .next()
                    .ok_or(fmt::Error)?;
                cursor += verb.len_utf8();
            }
            let value = values.get(argument).copied().flatten().ok_or(fmt::Error)?;
            argument += 1;
            match verb {
                's' if value.is_string() => {
                    for _ in value.text(scratch)?.chars().count()..width {
                        scratch.write_char(' ')?;
                    }
                    scratch.append(value)?;
                }
                'd' => match value {
                    ResultValue::Scalar(Some(Value::Int(v))) if zero => {
                        write!(scratch, "{v:0width$}")?
                    }
                    ResultValue::Scalar(Some(Value::Int(v))) => write!(scratch, "{v:width$}")?,
                    ResultValue::Uint(v) if zero => write!(scratch, "{v:0width$}")?,
                    ResultValue::Uint(v) => write!(scratch, "{v:width$}")?,
                    _ => return Err(fmt::Error),
                },
                'x' | 'X' => {
                    let (negative, number) = match value {
                        ResultValue::Scalar(Some(Value::Int(v))) => (v < 0, v.unsigned_abs()),
                        ResultValue::Uint(v) => (false, v),
                        _ => return Err(fmt::Error),
                    };
                    let digits = if number == 0 {
                        1
                    } else {
                        ((64 - number.leading_zeros()) as usize).div_ceil(4)
                    };
                    let padding = width.saturating_sub(digits + usize::from(negative));
                    if !zero {
                        for _ in 0..padding {
                            scratch.write_char(' ')?;
                        }
                    }
                    if negative {
                        scratch.write_char('-')?;
                    }
                    if zero {
                        for _ in 0..padding {
                            scratch.write_char('0')?;
                        }
                    }
                    if verb == 'x' {
                        write!(scratch, "{number:x}")?;
                    } else {
                        write!(scratch, "{number:X}")?;
                    }
                }
                'g' => match value {
                    ResultValue::Scalar(Some(Value::Float(v))) => write!(scratch, "{v}")?,
                    _ => return Err(fmt::Error),
                },
                't' => match value {
                    ResultValue::Scalar(Some(Value::Bool(v))) => write!(scratch, "{v}")?,
                    _ => return Err(fmt::Error),
                },
                'q' if value.is_string() => quote_value(value, scratch)?,
                'T' => scratch.write_str(value.type_name())?,
                'v' => scratch.append(value)?,
                _ => return Err(fmt::Error),
            }
        }
        return Ok(());
    }
    let mut previous_string = true;
    for (index, value) in values.iter().enumerate() {
        let value = value.ok_or(fmt::Error)?;
        if index != 0
            && (matches!(function, Function::Println) || (!previous_string && !value.is_string()))
        {
            scratch.write_char(' ')?;
        }
        scratch.append(value)?;
        previous_string = value.is_string();
    }
    if matches!(function, Function::Println) {
        scratch.write_char('\n')?;
    }
    Ok(())
}

fn quote_value(value: ResultValue<'_>, scratch: &mut Scratch<'_>) -> fmt::Result {
    scratch.write_char('"')?;
    let mut offset = 0;
    while offset < value.text(scratch)?.len() {
        let ch = value.text(scratch)?[offset..]
            .chars()
            .next()
            .ok_or(fmt::Error)?;
        offset += ch.len_utf8();
        match ch {
            '"' => scratch.write_str("\\\"")?,
            '\\' => scratch.write_str("\\\\")?,
            '\n' => scratch.write_str("\\n")?,
            '\r' => scratch.write_str("\\r")?,
            '\t' => scratch.write_str("\\t")?,
            '\u{7}' => scratch.write_str("\\a")?,
            '\u{8}' => scratch.write_str("\\b")?,
            '\u{b}' => scratch.write_str("\\v")?,
            '\u{c}' => scratch.write_str("\\f")?,
            ch if ch.is_ascii_control() => write!(scratch, "\\x{:02x}", ch as u32)?,
            _ => scratch.write_char(ch)?,
        }
    }
    scratch.write_char('"')
}

impl Scratch<'_> {
    fn append(&mut self, value: ResultValue<'_>) -> fmt::Result {
        match value {
            ResultValue::Stored(start, end) => {
                let new_end = self
                    .len
                    .checked_add(end - start)
                    .filter(|end| *end <= self.bytes.len())
                    .ok_or(fmt::Error)?;
                self.bytes.copy_within(start..end, self.len);
                self.len = new_end;
                Ok(())
            }
            ResultValue::Scalar(Some(Value::String(value))) => self.write_str(value),
            ResultValue::Scalar(Some(Value::Bool(value))) => write!(self, "{value}"),
            ResultValue::Scalar(Some(Value::Int(value))) => write!(self, "{value}"),
            ResultValue::Scalar(Some(Value::Float(value))) => write!(self, "{value}"),
            ResultValue::Scalar(None | Some(Value::Nil)) => self.write_str("<nil>"),
            ResultValue::Uint(value) => write!(self, "{value}"),
            ResultValue::Question(value) => write!(
                self,
                "{{{} {} {}}}",
                value.name, value.qtype.0, value.qclass.0
            ),
            _ => Err(fmt::Error),
        }
    }
}

impl<'a> ResultValue<'a> {
    fn truthy(self, scratch: &Scratch<'_>) -> bool {
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
            Self::Questions(value) => value.questions().next().is_some(),
            Self::Question(_) => true,
            Self::Stored(start, end) => {
                let _ = scratch;
                start != end
            }
        }
    }
    fn integer(self) -> Result<i64, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::Int(value))) => Ok(value),
            Self::Uint(value) => i64::try_from(value).map_err(|_| fmt::Error),
            _ => Err(fmt::Error),
        }
    }
    fn text<'s>(&'s self, scratch: &'s Scratch<'_>) -> Result<&'s str, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::String(value))) => Ok(value),
            Self::Stored(start, end) => {
                std::str::from_utf8(&scratch.bytes[*start..*end]).map_err(|_| fmt::Error)
            }
            _ => Err(fmt::Error),
        }
    }
    fn length(self, _scratch: &Scratch<'_>) -> Result<usize, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::String(value))) => Ok(value.len()),
            Self::Matches(value) => Ok(value.len()),
            Self::Groups(value) => Ok(value.len()),
            Self::Variables(value) => Ok(value.len()),
            Self::Questions(value) => Ok(value.questions().count()),
            Self::Stored(start, end) => Ok(end - start),
            _ => Err(fmt::Error),
        }
    }
    fn index(self, key: Self, scratch: &Scratch<'_>) -> Result<Self, fmt::Error> {
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
                    .find_map(|(name, value)| (*name == key.text(scratch).ok()?).then_some(*value))
                    .unwrap_or(""),
            )))),
            Self::Variables(values) => {
                Ok(Self::Scalar(values.iter().find_map(|(name, value)| {
                    (*name == key.text(scratch).ok()?).then_some(*value)
                })))
            }
            Self::Questions(message) => Ok(Self::Question(
                message
                    .questions()
                    .nth(usize::try_from(key.integer()?).map_err(|_| fmt::Error)?)
                    .ok_or(fmt::Error)?,
            )),
            Self::Scalar(Some(Value::String(value))) => Ok(Self::Uint(u64::from(
                *value
                    .as_bytes()
                    .get(usize::try_from(key.integer()?).map_err(|_| fmt::Error)?)
                    .ok_or(fmt::Error)?,
            ))),
            Self::Stored(start, end) => {
                let index = usize::try_from(key.integer()?).map_err(|_| fmt::Error)?;
                Ok(Self::Uint(u64::from(
                    *scratch
                        .bytes
                        .get(start..end)
                        .and_then(|bytes| bytes.get(index))
                        .ok_or(fmt::Error)?,
                )))
            }
            _ => Err(fmt::Error),
        }
    }
    fn slice(
        self,
        low: usize,
        high: usize,
        max: usize,
        three_index: bool,
        scratch: &Scratch<'_>,
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
            Self::Stored(start, end) if !three_index => {
                let text =
                    std::str::from_utf8(&scratch.bytes[start..end]).map_err(|_| fmt::Error)?;
                text.get(low..high).ok_or(fmt::Error)?;
                Ok(Self::Stored(start + low, start + high))
            }
            _ => Err(fmt::Error),
        }
    }
    fn equal(self, other: Self, scratch: &Scratch<'_>) -> Result<bool, fmt::Error> {
        if self.is_string() && other.is_string() {
            return Ok(self.text(scratch)? == other.text(scratch)?);
        }
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
    fn order(
        self,
        other: Self,
        scratch: &Scratch<'_>,
    ) -> Result<Option<std::cmp::Ordering>, fmt::Error> {
        if self.is_string() && other.is_string() {
            return Ok(Some(self.text(scratch)?.cmp(other.text(scratch)?)));
        }
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
    fn is_string(self) -> bool {
        matches!(
            self,
            Self::Stored(..) | Self::Scalar(Some(Value::String(_)))
        )
    }
    fn type_name(self) -> &'static str {
        match self {
            Self::Scalar(None | Some(Value::Nil)) => "<nil>",
            Self::Scalar(Some(Value::Bool(_))) => "bool",
            Self::Scalar(Some(Value::Int(_))) => "int",
            Self::Scalar(Some(Value::Float(_))) => "float64",
            Self::Scalar(Some(Value::String(_))) | Self::Stored(..) => "string",
            Self::Uint(_) => "uint64",
            Self::Matches(_) => "[]string",
            Self::Groups(_) => "map[string]string",
            Self::Variables(_) => "map[string]interface {}",
            Self::Questions(_) => "[]dns.Question",
            Self::Question(_) => "dns.Question",
        }
    }
}

fn atom(word: &str) -> Result<Atom, String> {
    if let Some((base, suffix)) = word.rsplit_once(").")
        && base.starts_with('(')
    {
        let member = super::QuestionMember::parse(suffix).ok_or("unsupported indexed field")?;
        return Ok(Atom::Select(
            Box::new(atom(&word[..base.len() + 1])?),
            member,
        ));
    }
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
            } else if let Some(value) = parse_base_integer(word) {
                Ok(Atom::Int(value))
            } else if (word.contains('.') || word.contains('e') || word.contains('E'))
                && word.parse::<f64>().is_ok()
            {
                Ok(Atom::Float(
                    word.parse::<f64>().map_err(|_| "invalid float")?,
                ))
            } else {
                Ok(Atom::Field(parse_field(word)?))
            }
        }
    }
}

fn parse_base_integer(word: &str) -> Option<i64> {
    let (negative, word) = word
        .strip_prefix('-')
        .map_or((false, word), |word| (true, word));
    let (radix, digits) =
        if let Some(value) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
            (16, value)
        } else if let Some(value) = word.strip_prefix("0o").or_else(|| word.strip_prefix("0O")) {
            (8, value)
        } else {
            (
                2,
                word.strip_prefix("0b")
                    .or_else(|| word.strip_prefix("0B"))?,
            )
        };
    let value = i64::from_str_radix(digits, radix).ok()?;
    Some(if negative {
        value.checked_neg()?
    } else {
        value
    })
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
