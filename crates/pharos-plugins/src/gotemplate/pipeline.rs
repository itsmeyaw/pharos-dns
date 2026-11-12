use super::{Data, Dot, Field, Value, compare, parse_field, parse_uint};
use std::fmt::{self, Write};

const MAX_ARGUMENTS: usize = 64;

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
    Printf(Box<crate::regex_match::ThreadRegex>),
    Html,
    Js(Box<crate::regex_match::ThreadRegex>),
    UrlQuery,
    Meta(bool),
    Call,
}
enum Command {
    Atom(Atom),
    Call(Function, Vec<Atom>),
}

pub(super) struct Pipeline(Vec<Command>);

#[derive(Clone, Copy)]
pub(super) struct QuestionSlice<'a> {
    pub message: &'a pharos_proto::Message<'a>,
    pub start: usize,
    pub end: usize,
}

impl<'a> QuestionSlice<'a> {
    pub(super) fn new(message: &'a pharos_proto::Message<'a>) -> Self {
        Self {
            message,
            start: 0,
            end: message.questions().count(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum RangeValue<'a> {
    Empty,
    Integer(i64),
    Matches(&'a [&'a str]),
    Groups(&'a [(&'a str, &'a str)]),
    Variables(&'a [(&'a str, Value<'a>)]),
    Questions(QuestionSlice<'a>),
}

#[derive(Clone, Copy)]
enum ResultValue<'a> {
    Scalar(Option<Value<'a>>),
    Uint(u64),
    Matches(&'a [&'a str]),
    Groups(&'a [(&'a str, &'a str)]),
    Variables(&'a [(&'a str, Value<'a>)]),
    Questions(QuestionSlice<'a>),
    Question(pharos_proto::Question<'a>),
    QuestionPointer(pharos_proto::Question<'a>),
    Stored(usize, usize),
}

struct ValueStack<'s, 'a> {
    slots: &'s mut [Option<ResultValue<'a>>],
    len: usize,
    call_buffer: &'s mut [u8],
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
                "printf" => Some(Function::Printf(Box::new(
                    crate::regex_match::ThreadRegex::new(r"^[\p{L}\p{M}\p{N}\p{P}\p{S}]$")?,
                ))),
                "html" => Some(Function::Html),
                "js" => Some(Function::Js(Box::new(
                    crate::regex_match::ThreadRegex::new(r"^[\p{L}\p{M}\p{N}\p{P}\p{S}]$")?,
                ))),
                "urlquery" => Some(Function::UrlQuery),
                ".Meta" => Some(Function::Meta(false)),
                "$.Meta" => Some(Function::Meta(true)),
                "call" => Some(Function::Call),
                _ => None,
            };
            let command = if let Some(function) = function {
                let args = words[1..]
                    .iter()
                    .map(|word| atom(word))
                    .collect::<Result<Vec<_>, _>>()?;
                // shortcut: 64 live argument slots bound stack use; use caller-owned slots for larger calls.
                if args.len() + usize::from(index != 0) > MAX_ARGUMENTS {
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
        let pipeline = Self(commands);
        if pipeline.required_slots() > MAX_ARGUMENTS {
            return Err("pipeline needs more than 64 live argument slots".into());
        }
        Ok(pipeline)
    }

    fn required_slots(&self) -> usize {
        self.0
            .iter()
            .enumerate()
            .map(|(stage, command)| match command {
                Command::Atom(atom) => atom.required_slots(),
                Command::Call(function, args) => {
                    let formatted = matches!(
                        function,
                        Function::Print
                            | Function::Println
                            | Function::Printf(_)
                            | Function::Html
                            | Function::Js(_)
                            | Function::UrlQuery
                    );
                    let nested = args
                        .iter()
                        .enumerate()
                        .map(|(index, atom)| usize::from(formatted) * index + atom.required_slots())
                        .max()
                        .unwrap_or(0);
                    nested.max(if formatted {
                        args.len() + usize::from(stage != 0)
                    } else {
                        0
                    })
                }
            })
            .max()
            .unwrap_or(0)
    }

    fn evaluate<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
        scratch: &mut Scratch<'_>,
        stack: &mut ValueStack<'_, 'a>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        let mut value = None;
        for command in &self.0 {
            value = Some(match command {
                Command::Atom(Atom::Nil) => return Err(fmt::Error),
                Command::Atom(atom) => atom.value(data, dot, scratch, stack)?,
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
                        Function::Index => count >= 1,
                        Function::Slice => (1..=4).contains(&count),
                        Function::Print
                        | Function::Println
                        | Function::Html
                        | Function::Js(_)
                        | Function::UrlQuery => true,
                        Function::Printf(_) => count >= 1,
                        Function::Meta(_) => count == 1,
                        Function::Call => count >= 1,
                    };
                    if !valid {
                        return Err(fmt::Error);
                    }
                    match function {
                        Function::Eq => {
                            let first = argument(args, 0, value, data, dot, scratch, stack)?;
                            let mut same = false;
                            for index in 1..count {
                                let other =
                                    argument(args, index, value, data, dot, scratch, stack)?;
                                same |= first.equal(other, scratch)?;
                            }
                            ResultValue::Scalar(Some(Value::Bool(same)))
                        }
                        Function::Ne => {
                            let a = argument(args, 0, value, data, dot, scratch, stack)?;
                            let b = argument(args, 1, value, data, dot, scratch, stack)?;
                            ResultValue::Scalar(Some(Value::Bool(!a.equal(b, scratch)?)))
                        }
                        Function::Lt | Function::Le | Function::Gt | Function::Ge => {
                            let a = argument(args, 0, value, data, dot, scratch, stack)?;
                            let b = argument(args, 1, value, data, dot, scratch, stack)?;
                            let ordering = a.order(b, scratch)?;
                            let result = match function {
                                Function::Lt => ordering.is_some_and(|v| v.is_lt()),
                                Function::Le => ordering.is_some_and(|v| v.is_le()),
                                Function::Gt => ordering.is_some_and(|v| v.is_gt()),
                                Function::Ge => ordering.is_some_and(|v| v.is_ge()),
                                _ => return Err(fmt::Error),
                            };
                            ResultValue::Scalar(Some(Value::Bool(result)))
                        }
                        Function::And | Function::Or => {
                            let mut result = argument(args, 0, value, data, dot, scratch, stack)?;
                            for index in 1..count {
                                if matches!(function, Function::And) && !result.truthy(scratch)
                                    || matches!(function, Function::Or) && result.truthy(scratch)
                                {
                                    break;
                                }
                                result = argument(args, index, value, data, dot, scratch, stack)?;
                            }
                            result
                        }
                        Function::Len => {
                            let input = argument(args, 0, value, data, dot, scratch, stack)?;
                            ResultValue::Scalar(Some(Value::Int(input.length(scratch)? as i64)))
                        }
                        Function::Not => {
                            let input = argument(args, 0, value, data, dot, scratch, stack)?;
                            ResultValue::Scalar(Some(Value::Bool(!input.truthy(scratch))))
                        }
                        Function::ParseInt => {
                            let input = argument(args, 0, value, data, dot, scratch, stack)?;
                            let base =
                                argument(args, 1, value, data, dot, scratch, stack)?.integer()?;
                            let bits =
                                argument(args, 2, value, data, dot, scratch, stack)?.integer()?;
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
                            let mut indexed = argument(args, 0, value, data, dot, scratch, stack)?;
                            if matches!(indexed, ResultValue::Scalar(None | Some(Value::Nil))) {
                                return Err(fmt::Error);
                            }
                            for index in 1..count {
                                let key = argument(args, index, value, data, dot, scratch, stack)?;
                                indexed = indexed.index(key, scratch)?;
                            }
                            indexed
                        }
                        Function::Meta(root) => {
                            if !root && !matches!(dot.base(), Dot::Root) {
                                return Err(fmt::Error);
                            }
                            let label = argument(args, 0, value, data, dot, scratch, stack)?;
                            let label = label.text(scratch)?;
                            let result = if data.metadata.enabled() {
                                data.metadata.get(label).unwrap_or("")
                            } else {
                                ""
                            };
                            ResultValue::Scalar(Some(Value::String(result)))
                        }
                        Function::Call => {
                            let ResultValue::Scalar(Some(Value::Function(function))) =
                                argument(args, 0, value, data, dot, scratch, stack)?
                            else {
                                return Err(fmt::Error);
                            };
                            if count > 3 {
                                return Err(fmt::Error);
                            }
                            let mut resolved = [None; 2];
                            for (index, slot) in resolved[..count - 1].iter_mut().enumerate() {
                                *slot = Some(argument(
                                    args,
                                    index + 1,
                                    value,
                                    data,
                                    dot,
                                    scratch,
                                    stack,
                                )?);
                            }
                            let mut parameters = [Value::Nil; 2];
                            for (index, argument) in resolved[..count - 1].iter().enumerate() {
                                let argument = argument.as_ref().ok_or(fmt::Error)?;
                                parameters[index] = match *argument {
                                    ResultValue::Scalar(Some(value)) => value,
                                    value if value.is_string() => {
                                        Value::String(argument.text(scratch)?)
                                    }
                                    _ => Value::Nil,
                                };
                            }
                            match function
                                .invoke(&parameters[..count - 1], stack.call_buffer)
                                .map_err(|_| fmt::Error)?
                            {
                                Value::String(value) => {
                                    let start = scratch.len;
                                    scratch.write_str(value)?;
                                    ResultValue::Stored(start, scratch.len)
                                }
                                Value::Bool(value) => ResultValue::Scalar(Some(Value::Bool(value))),
                                Value::Int(value) => ResultValue::Scalar(Some(Value::Int(value))),
                                Value::Float(value) => {
                                    ResultValue::Scalar(Some(Value::Float(value)))
                                }
                                Value::Nil => ResultValue::Scalar(Some(Value::Nil)),
                                Value::Function(_) => return Err(fmt::Error),
                            }
                        }
                        Function::Slice => {
                            let input = argument(args, 0, value, data, dot, scratch, stack)?;
                            let len = input.length(scratch)?;
                            let low = if count >= 2 {
                                usize::try_from(
                                    argument(args, 1, value, data, dot, scratch, stack)?
                                        .integer()?,
                                )
                                .map_err(|_| fmt::Error)?
                            } else {
                                0
                            };
                            let high = if count >= 3 {
                                usize::try_from(
                                    argument(args, 2, value, data, dot, scratch, stack)?
                                        .integer()?,
                                )
                                .map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            let max = if count == 4 {
                                usize::try_from(
                                    argument(args, 3, value, data, dot, scratch, stack)?
                                        .integer()?,
                                )
                                .map_err(|_| fmt::Error)?
                            } else {
                                len
                            };
                            input.slice(low, high, max, count == 4, scratch)?
                        }
                        Function::Print
                        | Function::Println
                        | Function::Printf(_)
                        | Function::Html
                        | Function::Js(_)
                        | Function::UrlQuery => {
                            let base = stack.len;
                            let end = base
                                .checked_add(count)
                                .filter(|end| *end <= stack.slots.len())
                                .ok_or(fmt::Error)?;
                            for index in 0..count {
                                let item = argument(args, index, value, data, dot, scratch, stack)?;
                                *stack.slots.get_mut(base + index).ok_or(fmt::Error)? = Some(item);
                                stack.len = base + index + 1;
                            }
                            let start = scratch.len;
                            if matches!(
                                function,
                                Function::Html | Function::Js(_) | Function::UrlQuery
                            ) {
                                format_values(
                                    &Function::Print,
                                    stack.slots.get(base..end).ok_or(fmt::Error)?,
                                    scratch,
                                )?;
                                let end = scratch.len;
                                escape_values(function, start, end, scratch)?;
                                stack.len = base;
                                ResultValue::Stored(end, scratch.len)
                            } else {
                                format_values(
                                    function,
                                    stack.slots.get(base..end).ok_or(fmt::Error)?,
                                    scratch,
                                )?;
                                stack.len = base;
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
        bytes: &mut [u8],
    ) -> fmt::Result {
        let mut scratch = Scratch { bytes, len: 0 };
        let mut slots = [None; MAX_ARGUMENTS];
        let mut call_buffer = [0; 2048];
        let mut stack = ValueStack {
            slots: &mut slots,
            len: 0,
            call_buffer: &mut call_buffer,
        };
        match self.evaluate(data, dot, &mut scratch, &mut stack)? {
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
            ResultValue::QuestionPointer(question) => {
                super::display::question_pointer(output, question)
            }
            ResultValue::Matches(values) => super::display::matches(output, values),
            ResultValue::Groups(values) => super::display::map(
                output,
                values
                    .iter()
                    .map(|(key, value)| (*key, Value::String(value))),
            ),
            ResultValue::Variables(values) => {
                super::display::map(output, values.iter().map(|(key, value)| (*key, *value)))
            }
            ResultValue::Questions(values) => super::display::questions(output, values),
        }
    }

    pub(super) fn truthy(
        &self,
        data: &Data<'_, '_>,
        dot: Dot<'_>,
        bytes: &mut [u8],
    ) -> Result<bool, fmt::Error> {
        let mut scratch = Scratch { bytes, len: 0 };
        let mut slots = [None; MAX_ARGUMENTS];
        let mut call_buffer = [0; 2048];
        let mut stack = ValueStack {
            slots: &mut slots,
            len: 0,
            call_buffer: &mut call_buffer,
        };
        Ok(self
            .evaluate(data, dot, &mut scratch, &mut stack)?
            .truthy(&scratch))
    }

    pub(super) fn range<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
        bytes: &mut [u8],
    ) -> Result<RangeValue<'a>, fmt::Error> {
        let mut scratch = Scratch { bytes, len: 0 };
        let mut slots = [None; MAX_ARGUMENTS];
        let mut call_buffer = [0; 2048];
        let mut stack = ValueStack {
            slots: &mut slots,
            len: 0,
            call_buffer: &mut call_buffer,
        };
        match self.evaluate(data, dot, &mut scratch, &mut stack)? {
            ResultValue::Scalar(None | Some(Value::Nil)) => Ok(RangeValue::Empty),
            ResultValue::Scalar(Some(Value::Int(value))) => Ok(RangeValue::Integer(value)),
            ResultValue::Uint(value) => Ok(RangeValue::Integer(
                i64::try_from(value).map_err(|_| fmt::Error)?,
            )),
            ResultValue::Matches(values) => Ok(RangeValue::Matches(values)),
            ResultValue::Groups(values) => Ok(RangeValue::Groups(values)),
            ResultValue::Variables(values) => Ok(RangeValue::Variables(values)),
            ResultValue::Questions(questions) => Ok(RangeValue::Questions(questions)),
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
        let window = &scratch.bytes[offset..end.min(offset.saturating_add(4))];
        let valid = match std::str::from_utf8(window) {
            Ok(text) => text,
            Err(error) => {
                std::str::from_utf8(&window[..error.valid_up_to()]).map_err(|_| fmt::Error)?
            }
        };
        let ch = valid.chars().next().ok_or(fmt::Error)?;
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
    fn required_slots(&self) -> usize {
        match self {
            Self::Nested(pipeline) => pipeline.required_slots(),
            Self::Select(atom, _) => atom.required_slots(),
            _ => 0,
        }
    }
    fn value<'a>(
        &'a self,
        data: &'a Data<'_, '_>,
        dot: Dot<'a>,
        scratch: &mut Scratch<'_>,
        stack: &mut ValueStack<'_, 'a>,
    ) -> Result<ResultValue<'a>, fmt::Error> {
        match self {
            Self::Int(value) => Ok(ResultValue::Scalar(Some(Value::Int(*value)))),
            Self::Float(value) => Ok(ResultValue::Scalar(Some(Value::Float(*value)))),
            Self::Bool(value) => Ok(ResultValue::Scalar(Some(Value::Bool(*value)))),
            Self::Nil => Ok(ResultValue::Scalar(Some(Value::Nil))),
            Self::Nested(pipeline) => pipeline.evaluate(data, dot, scratch, stack),
            Self::Field(Field::Local(name)) if dot.local_range(name).is_some() => {
                Ok(match dot.local_range(name).ok_or(fmt::Error)? {
                    RangeValue::Empty => ResultValue::Scalar(None),
                    RangeValue::Integer(value) => ResultValue::Scalar(Some(Value::Int(value))),
                    RangeValue::Matches(value) => ResultValue::Matches(value),
                    RangeValue::Groups(value) => ResultValue::Groups(value),
                    RangeValue::Variables(value) => ResultValue::Variables(value),
                    RangeValue::Questions(value) => ResultValue::Questions(value),
                })
            }
            Self::Field(Field::Dot) if matches!(dot.base(), Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot.base() else {
                    return Err(fmt::Error);
                };
                Ok(ResultValue::Question(value))
            }
            Self::Select(atom, member) => {
                let ResultValue::Question(question) = atom.value(data, dot, scratch, stack)? else {
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
            Self::Field(Field::Name) if matches!(dot.base(), Dot::Question { .. }) => {
                let Dot::Question { value, .. } = dot.base() else {
                    return Err(fmt::Error);
                };
                let start = scratch.len;
                write!(scratch, "{}", value.name)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::QuestionName) if matches!(dot.base(), Dot::Root) => {
                let start = scratch.len;
                write!(scratch, "{}", super::question_name(data)?)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::Question) if matches!(dot.base(), Dot::Root) => {
                Ok(ResultValue::QuestionPointer(super::question(data)?))
            }
            Self::Field(Field::Root(field)) if matches!(field.as_ref(), Field::Question) => {
                Ok(ResultValue::QuestionPointer(super::question(data)?))
            }
            Self::Field(Field::Root(field)) if matches!(field.as_ref(), Field::QuestionName) => {
                let start = scratch.len;
                write!(scratch, "{}", super::question_name(data)?)?;
                Ok(ResultValue::Stored(start, scratch.len))
            }
            Self::Field(Field::Matches) if matches!(dot.base(), Dot::Root) => {
                Ok(ResultValue::Matches(data.matches))
            }
            Self::Field(Field::Groups) if matches!(dot.base(), Dot::Root) => {
                Ok(ResultValue::Groups(data.groups))
            }
            Self::Field(Field::Variables) if matches!(dot.base(), Dot::Root) => {
                Ok(ResultValue::Variables(data.variables))
            }
            Self::Field(Field::Questions) if matches!(dot.base(), Dot::Root) => Ok(
                ResultValue::Questions(QuestionSlice::new(data.message.ok_or(fmt::Error)?)),
            ),
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
                    Field::Questions => Ok(ResultValue::Questions(QuestionSlice::new(
                        data.message.ok_or(fmt::Error)?,
                    ))),
                    _ => Err(fmt::Error),
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
    stack: &mut ValueStack<'_, 'a>,
) -> Result<ResultValue<'a>, fmt::Error> {
    if let Some(atom) = args.get(index) {
        atom.value(data, dot, scratch, stack)
    } else {
        previous.ok_or(fmt::Error)
    }
}

fn format_values(
    function: &Function,
    values: &[Option<ResultValue<'_>>],
    scratch: &mut Scratch<'_>,
) -> fmt::Result {
    if let Function::Printf(printable) = function {
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
            let Some(mut verb) = format.text(scratch)?[cursor..].chars().next() else {
                scratch.write_str("%!(NOVERB)")?;
                break;
            };
            cursor += verb.len_utf8();
            if verb == '%' {
                scratch.write_char('%')?;
                continue;
            }
            let (mut zero, mut left, mut plus, mut alternate) = (false, false, false, false);
            while matches!(verb, '0' | '-' | '+' | '#') {
                match verb {
                    '0' => zero = true,
                    '-' => left = true,
                    '+' => plus = true,
                    '#' => alternate = true,
                    _ => return Err(fmt::Error),
                }
                verb = format.text(scratch)?[cursor..]
                    .chars()
                    .next()
                    .ok_or(fmt::Error)?;
                cursor += verb.len_utf8();
            }
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
            let mut precision = None;
            if verb == '.' {
                let mut digits = 0usize;
                verb = format.text(scratch)?[cursor..]
                    .chars()
                    .next()
                    .ok_or(fmt::Error)?;
                cursor += verb.len_utf8();
                while verb.is_ascii_digit() {
                    digits = digits
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(verb.to_digit(10)? as usize))
                        .ok_or(fmt::Error)?;
                    if digits > 65535 {
                        return Err(fmt::Error);
                    }
                    verb = format.text(scratch)?[cursor..]
                        .chars()
                        .next()
                        .ok_or(fmt::Error)?;
                    cursor += verb.len_utf8();
                }
                precision = Some(digits);
            }
            let Some(value) = values.get(argument).copied().flatten() else {
                write!(scratch, "%!{verb}(MISSING)")?;
                continue;
            };
            argument += 1;
            let compatible = match verb {
                's' => value.is_string() || matches!(value, ResultValue::QuestionPointer(_)),
                'q' => {
                    value.is_string()
                        || matches!(
                            value,
                            ResultValue::Scalar(Some(Value::Int(_))) | ResultValue::Uint(_)
                        )
                }
                'd' | 'x' | 'X' | 'o' | 'b' | 'c' => matches!(
                    value,
                    ResultValue::Scalar(Some(Value::Int(_))) | ResultValue::Uint(_)
                ),
                'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                    matches!(value, ResultValue::Scalar(Some(Value::Float(_))))
                }
                't' => matches!(value, ResultValue::Scalar(Some(Value::Bool(_)))),
                'T' | 'v' => true,
                _ => false,
            };
            if !compatible {
                write!(scratch, "%!{verb}({}=", value.type_name())?;
                scratch.append(value)?;
                scratch.write_char(')')?;
                continue;
            }
            match verb {
                's' if value.is_string() => {
                    let text = value.text(scratch)?;
                    let end = precision
                        .and_then(|n| text.char_indices().nth(n).map(|(index, _)| index))
                        .unwrap_or(text.len());
                    let chars = text[..end].chars().count();
                    let value = value.prefix(end)?;
                    if !left {
                        for _ in chars..width {
                            scratch.write_char(if zero { '0' } else { ' ' })?;
                        }
                    }
                    scratch.append(value)?;
                    if left {
                        for _ in chars..width {
                            scratch.write_char(' ')?;
                        }
                    }
                }
                's' if matches!(value, ResultValue::QuestionPointer(_)) => {
                    if precision.is_some() {
                        return Err(fmt::Error);
                    }
                    let start = scratch.len;
                    scratch.append(value)?;
                    pad_segment(scratch, start, width, left, zero)?;
                }
                'd' | 'x' | 'X' | 'o' | 'b' => {
                    let (negative, number) = match value {
                        ResultValue::Scalar(Some(Value::Int(v))) => (v < 0, v.unsigned_abs()),
                        ResultValue::Uint(v) => (false, v),
                        _ => return Err(fmt::Error),
                    };
                    let bits = (64 - number.leading_zeros()) as usize;
                    let digits = if number == 0 && precision == Some(0) {
                        0
                    } else {
                        match verb {
                            'x' | 'X' => bits.div_ceil(4).max(1),
                            'o' => bits.div_ceil(3).max(1),
                            'b' => bits.max(1),
                            _ => number.checked_ilog10().map_or(1, |n| n as usize + 1),
                        }
                    };
                    let leading = precision.unwrap_or(0).saturating_sub(digits);
                    let prefix = if alternate {
                        match verb {
                            'x' => "0x",
                            'X' => "0X",
                            'b' => "0b",
                            'o' if number != 0 => "0",
                            _ => "",
                        }
                    } else {
                        ""
                    };
                    let signed = negative || plus;
                    let padding =
                        width.saturating_sub(digits + leading + usize::from(signed) + prefix.len());
                    if (!zero || precision.is_some()) && !left {
                        for _ in 0..padding {
                            scratch.write_char(' ')?;
                        }
                    }
                    if negative {
                        scratch.write_char('-')?;
                    } else if plus {
                        scratch.write_char('+')?;
                    }
                    scratch.write_str(prefix)?;
                    if zero && !left && precision.is_none() {
                        for _ in 0..padding {
                            scratch.write_char('0')?;
                        }
                    }
                    for _ in 0..leading {
                        scratch.write_char('0')?;
                    }
                    if digits != 0 {
                        match verb {
                            'x' => write!(scratch, "{number:x}")?,
                            'X' => write!(scratch, "{number:X}")?,
                            'o' => write!(scratch, "{number:o}")?,
                            'b' => write!(scratch, "{number:b}")?,
                            _ => write!(scratch, "{number}")?,
                        }
                    }
                    if left {
                        for _ in 0..padding {
                            scratch.write_char(' ')?;
                        }
                    }
                }
                'f' | 'F' => match value {
                    ResultValue::Scalar(Some(Value::Float(v))) => {
                        let precision = precision.unwrap_or(6);
                        let start = scratch.len;
                        if v.is_finite() {
                            if plus {
                                write!(scratch, "{v:+.precision$}")?;
                            } else {
                                write!(scratch, "{v:.precision$}")?;
                            }
                            if alternate && precision == 0 {
                                scratch.write_char('.')?;
                            }
                        } else {
                            if plus && v.is_nan() {
                                scratch.write_char('+')?;
                            }
                            super::float::write_float(scratch, v)?;
                        }
                        pad_segment(scratch, start, width, left, zero && v.is_finite())?;
                    }
                    _ => return Err(fmt::Error),
                },
                'e' | 'E' => match value {
                    ResultValue::Scalar(Some(Value::Float(v))) => {
                        let start = scratch.len;
                        if plus && v.is_sign_positive() && v.is_finite() {
                            scratch.write_char('+')?;
                        }
                        if plus && v.is_nan() {
                            scratch.write_char('+')?;
                        }
                        super::float::write_e(
                            scratch,
                            v,
                            precision.unwrap_or(6),
                            verb == 'E',
                            alternate,
                        )?;
                        pad_segment(scratch, start, width, left, zero && v.is_finite())?;
                    }
                    _ => return Err(fmt::Error),
                },
                'g' | 'G' => match value {
                    ResultValue::Scalar(Some(Value::Float(v))) => {
                        let start = scratch.len;
                        if plus && v.is_sign_positive() && v.is_finite() {
                            scratch.write_char('+')?;
                        }
                        if precision.is_some() || alternate {
                            super::float::write_g(scratch, v, precision.unwrap_or(6), alternate)?;
                        } else {
                            super::float::write_float(scratch, v)?;
                        }
                        if verb == 'G' {
                            for byte in &mut scratch.bytes[start..scratch.len] {
                                if *byte == b'e' {
                                    *byte = b'E';
                                }
                            }
                        }
                        pad_segment(scratch, start, width, left, zero)?;
                    }
                    _ => return Err(fmt::Error),
                },
                't' => match value {
                    ResultValue::Scalar(Some(Value::Bool(v))) => {
                        let start = scratch.len;
                        write!(scratch, "{v}")?;
                        pad_segment(scratch, start, width, left, zero)?;
                    }
                    _ => return Err(fmt::Error),
                },
                'q' if value.is_string() => {
                    let start = scratch.len;
                    let text = value.text(scratch)?;
                    let end = precision
                        .and_then(|n| text.char_indices().nth(n).map(|(index, _)| index))
                        .unwrap_or(text.len());
                    let value = value.prefix(end)?;
                    let raw = alternate
                        && value.text(scratch)?.chars().all(|ch| {
                            ch != '`'
                                && ch != '\u{feff}'
                                && (ch as u32 >= 128 || (!ch.is_ascii_control() || ch == '\t'))
                        });
                    if raw {
                        scratch.write_char('`')?;
                        scratch.append(value)?;
                        scratch.write_char('`')?;
                    } else {
                        quote_value(value, scratch, printable, plus)?;
                    }
                    pad_segment(scratch, start, width, left, zero)?;
                }
                'q' => {
                    let start = scratch.len;
                    let scalar = u32::try_from(value.integer()?).unwrap_or(u32::MAX);
                    let ch = char::from_u32(scalar).unwrap_or('\u{fffd}');
                    scratch.write_char('\'')?;
                    write_quoted_char(scratch, ch, '\'', plus, printable)?;
                    scratch.write_char('\'')?;
                    pad_segment(scratch, start, width, left, zero)?;
                }
                'c' => {
                    let start = scratch.len;
                    let scalar = u32::try_from(value.integer()?).unwrap_or(u32::MAX);
                    scratch.write_char(char::from_u32(scalar).unwrap_or('\u{fffd}'))?;
                    pad_segment(scratch, start, width, left, zero)?;
                }
                'T' => {
                    let start = scratch.len;
                    scratch.write_str(value.type_name())?;
                    pad_segment(scratch, start, width, left, zero)?;
                }
                'v' => {
                    let start = scratch.len;
                    scratch.append(value)?;
                    pad_segment(scratch, start, width, left, zero)?;
                }
                _ => return Err(fmt::Error),
            }
        }
        if argument < values.len() {
            scratch.write_str("%!(EXTRA ")?;
            for (index, value) in values[argument..].iter().enumerate() {
                let value = value.ok_or(fmt::Error)?;
                if index != 0 {
                    scratch.write_str(", ")?;
                }
                write!(scratch, "{}=", value.type_name())?;
                scratch.append(value)?;
            }
            scratch.write_char(')')?;
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

fn pad_segment(
    scratch: &mut Scratch<'_>,
    start: usize,
    width: usize,
    left: bool,
    zero: bool,
) -> fmt::Result {
    let text = std::str::from_utf8(&scratch.bytes[start..scratch.len]).map_err(|_| fmt::Error)?;
    let count = width.saturating_sub(text.chars().count());
    if count == 0 {
        return Ok(());
    }
    if left {
        for _ in 0..count {
            scratch.write_char(' ')?;
        }
        return Ok(());
    }
    let end = scratch.len;
    let new_end = end
        .checked_add(count)
        .filter(|end| *end <= scratch.bytes.len())
        .ok_or(fmt::Error)?;
    let sign = zero && matches!(scratch.bytes.get(start), Some(b'-' | b'+'));
    let begin = start + usize::from(sign);
    scratch.bytes.copy_within(begin..end, begin + count);
    scratch.bytes[begin..begin + count].fill(if zero { b'0' } else { b' ' });
    scratch.len = new_end;
    Ok(())
}

fn quote_value(
    value: ResultValue<'_>,
    scratch: &mut Scratch<'_>,
    printable: &crate::regex_match::ThreadRegex,
    ascii_only: bool,
) -> fmt::Result {
    scratch.write_char('"')?;
    let mut offset = 0;
    while offset < value.text(scratch)?.len() {
        let ch = value.text(scratch)?[offset..]
            .chars()
            .next()
            .ok_or(fmt::Error)?;
        offset += ch.len_utf8();
        write_quoted_char(scratch, ch, '"', ascii_only, printable)?;
    }
    scratch.write_char('"')
}

fn write_quoted_char(
    scratch: &mut Scratch<'_>,
    ch: char,
    quote: char,
    ascii_only: bool,
    printable: &crate::regex_match::ThreadRegex,
) -> fmt::Result {
    match ch {
        ch if ch == quote => {
            scratch.write_char('\\')?;
            scratch.write_char(ch)
        }
        '\\' => scratch.write_str("\\\\"),
        '\n' => scratch.write_str("\\n"),
        '\r' => scratch.write_str("\\r"),
        '\t' => scratch.write_str("\\t"),
        '\u{7}' => scratch.write_str("\\a"),
        '\u{8}' => scratch.write_str("\\b"),
        '\u{b}' => scratch.write_str("\\v"),
        '\u{c}' => scratch.write_str("\\f"),
        ch if ch.is_ascii_control() => write!(scratch, "\\x{:02x}", ch as u32),
        ch if !ch.is_ascii()
            && (ascii_only || !printable.is_match(ch.encode_utf8(&mut [0; 4]))) =>
        {
            if (ch as u32) <= 0xffff {
                write!(scratch, "\\u{:04x}", ch as u32)
            } else {
                write!(scratch, "\\U{:08x}", ch as u32)
            }
        }
        _ => scratch.write_char(ch),
    }
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
            ResultValue::Scalar(Some(Value::Float(value))) => {
                super::float::write_float(self, value)
            }
            ResultValue::Scalar(None | Some(Value::Nil)) => self.write_str("<nil>"),
            ResultValue::Uint(value) => write!(self, "{value}"),
            ResultValue::Question(value) => write!(
                self,
                "{{{} {} {}}}",
                value.name, value.qtype.0, value.qclass.0
            ),
            ResultValue::QuestionPointer(value) => super::display::question_pointer(self, value),
            ResultValue::Matches(values) => super::display::matches(self, values),
            ResultValue::Groups(values) => super::display::map(
                self,
                values
                    .iter()
                    .map(|(key, value)| (*key, Value::String(value))),
            ),
            ResultValue::Variables(values) => {
                super::display::map(self, values.iter().map(|(key, value)| (*key, *value)))
            }
            ResultValue::Questions(values) => super::display::questions(self, values),
            _ => Err(fmt::Error),
        }
    }
}

impl<'a> ResultValue<'a> {
    fn prefix(self, end: usize) -> Result<Self, fmt::Error> {
        match self {
            Self::Scalar(Some(Value::String(value))) => Ok(Self::Scalar(Some(Value::String(
                value.get(..end).ok_or(fmt::Error)?,
            )))),
            Self::Stored(start, limit) if start + end <= limit => {
                Ok(Self::Stored(start, start + end))
            }
            _ => Err(fmt::Error),
        }
    }
    fn truthy(self, scratch: &Scratch<'_>) -> bool {
        match self {
            Self::Scalar(None | Some(Value::Nil)) => false,
            Self::Scalar(Some(Value::Bool(value))) => value,
            Self::Scalar(Some(Value::Int(value))) => value != 0,
            Self::Scalar(Some(Value::Float(value))) => value != 0.0,
            Self::Scalar(Some(Value::String(value))) => !value.is_empty(),
            Self::Scalar(Some(Value::Function(_))) => true,
            Self::Uint(value) => value != 0,
            Self::Matches(value) => !value.is_empty(),
            Self::Groups(value) => !value.is_empty(),
            Self::Variables(value) => !value.is_empty(),
            Self::Questions(value) => value.start < value.end,
            Self::Question(_) => true,
            Self::QuestionPointer(_) => true,
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
            Self::Questions(value) => Ok(value.end - value.start),
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
            Self::Groups(values) => {
                let key = key.text(scratch)?;
                Ok(Self::Scalar(Some(Value::String(
                    values
                        .iter()
                        .find_map(|(name, value)| (*name == key).then_some(*value))
                        .unwrap_or(""),
                ))))
            }
            Self::Variables(values) => {
                let key = key.text(scratch)?;
                Ok(Self::Scalar(values.iter().find_map(|(name, value)| {
                    (*name == key).then_some(*value)
                })))
            }
            Self::Questions(questions) => {
                let index = usize::try_from(key.integer()?).map_err(|_| fmt::Error)?;
                if index >= questions.end - questions.start {
                    return Err(fmt::Error);
                }
                Ok(Self::Question(
                    questions
                        .message
                        .questions()
                        .nth(questions.start + index)
                        .ok_or(fmt::Error)?,
                ))
            }
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
            Self::Questions(questions) => {
                if max > questions.end - questions.start {
                    return Err(fmt::Error);
                }
                Ok(Self::Questions(QuestionSlice {
                    message: questions.message,
                    start: questions.start + low,
                    end: questions.start + high,
                }))
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
            Self::Scalar(Some(Value::Function(value))) => value.type_name(),
            Self::Uint(_) => "uint64",
            Self::Matches(_) => "[]string",
            Self::Groups(_) => "map[string]string",
            Self::Variables(_) => "map[string]interface {}",
            Self::Questions(_) => "[]dns.Question",
            Self::Question(_) => "dns.Question",
            Self::QuestionPointer(_) => "*dns.Question",
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
        // shortcut: cap nested pipelines at eight levels; use iterative parsing to lift the stack limit.
        if quote.is_none() && ch == '(' {
            depth += 1;
            if depth > super::MAX_NESTING {
                return Err("pipeline nesting exceeds eight levels".into());
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

#[cfg(test)]
mod escape_tests {
    use super::{Function, Scratch, escape_values};

    #[test]
    fn malformed_or_truncated_escape_input_returns_error() {
        for input in [&b"a\xff"[..], &b"a\xf0\x9f\xa6"[..], &b"\xed\xa0\x80"[..]] {
            let mut buffer = [0; 32];
            buffer[..input.len()].copy_from_slice(input);
            let mut scratch = Scratch {
                bytes: &mut buffer,
                len: input.len(),
            };
            assert!(escape_values(&Function::Html, 0, input.len(), &mut scratch).is_err());
        }
    }
}
