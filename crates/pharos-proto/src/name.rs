use std::{
    cmp::Ordering,
    fmt::{self, Write},
    hash::{Hash, Hasher},
    str::FromStr,
};

// RFC 1035 §2.3.4: wire names are at most 255 octets and labels at most 63 octets.
const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
const MAX_POINTER_HOPS: usize = 255;
const MAX_LABELS: usize = 127;

/// An absolute domain name used in configuration and authoritative data.
#[derive(Clone, Debug)]
pub struct Name {
    wire: Vec<u8>,
}

/// The domain name used to resolve a relative presentation name.
pub type Origin = Name;

/// A borrowed domain name within a DNS message.
#[derive(Clone, Copy, Debug)]
pub struct NameRef<'a> {
    message: &'a [u8],
    offset: usize,
    wire_len: usize,
}

/// A malformed domain name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NameError {
    EmptyLabel,
    InvalidEscape,
    InvalidLabelType,
    LabelTooLong,
    NameTooLong,
    PointerLimit,
    PointerNotBackwards,
    RelativeName,
    Truncated,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyLabel => "empty label",
            Self::InvalidEscape => "invalid escape",
            Self::InvalidLabelType => "invalid label type",
            Self::LabelTooLong => "label exceeds 63 octets",
            Self::NameTooLong => "name exceeds 255 octets",
            Self::PointerLimit => "too many compression pointers",
            Self::PointerNotBackwards => "compression pointer is not backwards",
            Self::RelativeName => "absolute name must end in an unescaped dot",
            Self::Truncated => "truncated name",
        })
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// Parses a presentation name, resolving relative names against `origin`.
    pub fn parse(value: &str, origin: &Origin) -> Result<Self, NameError> {
        // RFC 1035 §5.1: @ denotes the current origin; relative names append it.
        if value == "@" {
            return Ok(origin.clone());
        }
        if is_absolute(value) {
            return Self::parse_absolute(value);
        }

        let mut relative = Self::parse_labels(value)?;
        relative.extend_from_slice(&origin.wire);
        check_uncompressed(&relative)?;
        Ok(Self { wire: relative })
    }

    /// Returns the canonical lowercase presentation form.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut output = String::new();
        write_presentation(&mut output, labels(&self.wire), true)
            .expect("writing to a String cannot fail");
        output
    }

    /// Returns the uncompressed wire encoding.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the number of non-root labels.
    #[must_use]
    pub fn label_count(&self) -> usize {
        label_offsets(&self.wire).1
    }

    /// Returns whether this name is at or below `domain`.
    #[must_use]
    pub fn is_subdomain_of(&self, domain: &Self) -> bool {
        let (self_offsets, self_count) = label_offsets(&self.wire);
        let (domain_offsets, domain_count) = label_offsets(&domain.wire);
        self_count >= domain_count
            && (0..domain_count).all(|index| {
                equal_label(
                    label_at(&self.wire, self_offsets[self_count - domain_count + index]),
                    label_at(&domain.wire, domain_offsets[index]),
                )
            })
    }

    /// Returns the parent name, or `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        (self.wire[0] != 0).then(|| Self {
            wire: self.wire[1 + usize::from(self.wire[0])..].to_vec(),
        })
    }

    /// Returns the most specific candidate domain containing `name`.
    #[must_use]
    pub fn longest_match<I>(name: &Self, candidates: I) -> Option<Self>
    where
        I: IntoIterator<Item = Self>,
    {
        candidates
            .into_iter()
            .filter(|candidate| name.is_subdomain_of(candidate))
            .max_by_key(Self::label_count)
    }

    fn parse_absolute(value: &str) -> Result<Self, NameError> {
        if !is_absolute(value) {
            return Err(NameError::RelativeName);
        }
        if value == "." {
            return Ok(Self { wire: vec![0] });
        }
        let mut wire = Self::parse_labels(&value[..value.len() - 1])?;
        wire.push(0);
        check_uncompressed(&wire)?;
        Ok(Self { wire })
    }

    fn parse_labels(value: &str) -> Result<Vec<u8>, NameError> {
        if value.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        let mut wire = Vec::with_capacity(value.len() + 1);
        let mut label = Vec::new();
        let bytes = value.as_bytes();
        let mut position = 0;
        while position < bytes.len() {
            match bytes[position] {
                b'.' => {
                    push_label(&mut wire, &label)?;
                    label.clear();
                    position += 1;
                }
                // RFC 4343 §2.1: escapes represent literal octets or three-digit decimal values.
                b'\\' => {
                    position += 1;
                    let escaped = bytes.get(position).ok_or(NameError::InvalidEscape)?;
                    if let Some(digits) = bytes
                        .get(position..position + 3)
                        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                    {
                        let number = u16::from(digits[0] - b'0') * 100
                            + u16::from(digits[1] - b'0') * 10
                            + u16::from(digits[2] - b'0');
                        label.push(u8::try_from(number).map_err(|_| NameError::InvalidEscape)?);
                        position += 3;
                    } else {
                        label.push(*escaped);
                        position += 1;
                    }
                }
                byte => {
                    label.push(byte);
                    position += 1;
                }
            }
        }
        push_label(&mut wire, &label)?;
        Ok(wire)
    }
}

fn is_absolute(value: &str) -> bool {
    value.ends_with('.')
        && value.as_bytes()[..value.len() - 1]
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count()
            % 2
            == 0
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_absolute(value)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_presentation(formatter, labels(&self.wire), false)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        equal_labels(labels(&self.wire), labels(&other.wire))
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in &self.wire {
            ascii_lower(*byte).hash(state);
        }
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        // RFC 4034 §6.1: canonical name order compares labels from right to left.
        let (left_offsets, left_count) = label_offsets(&self.wire);
        let (right_offsets, right_count) = label_offsets(&other.wire);
        for index in 0..left_count.min(right_count) {
            let result = canonical_label_cmp(
                label_at(&self.wire, left_offsets[left_count - index - 1]),
                label_at(&other.wire, right_offsets[right_count - index - 1]),
            );
            if result != Ordering::Equal {
                return result;
            }
        }
        left_count.cmp(&right_count)
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> NameRef<'a> {
    /// Validates and borrows the name at `offset` in a DNS message.
    pub fn parse(message: &'a [u8], offset: usize) -> Result<Self, NameError> {
        let wire_len = check_message_name(message, offset)?;
        Ok(Self {
            message,
            offset,
            wire_len,
        })
    }

    /// Returns the encoded length at the original message offset.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.wire_len
    }

    /// Returns the name's original offset in its Message.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Walks the encoded labels and compression pointers, including pointer targets.
    #[must_use]
    pub fn wire_parts(&self) -> NameWireParts<'a> {
        NameWireParts {
            message: self.message,
            position: Some(self.offset),
        }
    }

    /// Returns an iterator over labels without copying the name.
    #[must_use]
    pub fn labels(&self) -> NameRefLabels<'a> {
        NameRefLabels {
            message: self.message,
            position: self.offset,
            remaining_hops: MAX_POINTER_HOPS,
            done: false,
        }
    }

    /// Copies this potentially compressed name into an owned name.
    #[must_use]
    pub fn to_name(&self) -> Name {
        let mut wire = Vec::with_capacity(MAX_NAME_LEN);
        for label in self.labels() {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        Name { wire }
    }
}

/// One physical part of a validated name encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameWirePart {
    /// Encoded label, including its length octet.
    Label { offset: usize, len: usize },
    /// Terminal root octet.
    Root { offset: usize },
    /// Compression pointer and its target, both relative to the Message.
    Pointer { offset: usize, target: usize },
}

/// Allocation-free traversal of a validated name and its pointer chain.
pub struct NameWireParts<'a> {
    message: &'a [u8],
    position: Option<usize>,
}

impl Iterator for NameWireParts<'_> {
    type Item = NameWirePart;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.position?;
        let byte = self.message[offset];
        match byte {
            0 => {
                self.position = None;
                Some(NameWirePart::Root { offset })
            }
            1..=63 => {
                let len = usize::from(byte) + 1;
                self.position = Some(offset + len);
                Some(NameWirePart::Label { offset, len })
            }
            _ => {
                let target = usize::from(byte & 0x3f) << 8 | usize::from(self.message[offset + 1]);
                self.position = Some(target);
                Some(NameWirePart::Pointer { offset, target })
            }
        }
    }
}

impl fmt::Display for NameRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_presentation(formatter, self.labels(), false)
    }
}

impl PartialEq<Name> for NameRef<'_> {
    fn eq(&self, other: &Name) -> bool {
        equal_labels(self.labels(), labels(&other.wire))
    }
}

impl PartialEq for NameRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        equal_labels(self.labels(), other.labels())
    }
}

impl Eq for NameRef<'_> {}

/// An allocation-free iterator over labels in a borrowed message name.
pub struct NameRefLabels<'a> {
    message: &'a [u8],
    position: usize,
    remaining_hops: usize,
    done: bool,
}

impl<'a> Iterator for NameRefLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let length = *self.message.get(self.position)?;
        match length {
            0 => {
                self.done = true;
                None
            }
            1..=63 => {
                let start = self.position + 1;
                let label = self.message.get(start..start + usize::from(length))?;
                self.position = start + usize::from(length);
                Some(label)
            }
            0xc0..=0xff => {
                if self.remaining_hops == 0 {
                    self.done = true;
                    return None;
                }
                let target = usize::from(length & 0x3f) << 8
                    | usize::from(*self.message.get(self.position + 1)?);
                self.position = target;
                self.remaining_hops -= 1;
                self.next()
            }
            _ => {
                self.done = true;
                None
            }
        }
    }
}

fn check_message_name(message: &[u8], offset: usize) -> Result<usize, NameError> {
    let mut position = offset;
    let mut wire_len = 0;
    let mut expanded_len = 0;
    let mut hops = 0;
    let mut jumped = false;
    let mut pointer_limit = message.len();
    loop {
        if jumped && position >= pointer_limit {
            return Err(NameError::PointerNotBackwards);
        }
        let length = *message.get(position).ok_or(NameError::Truncated)?;
        match length {
            0 => {
                expanded_len += 1;
                if expanded_len > MAX_NAME_LEN {
                    return Err(NameError::NameTooLong);
                }
                return Ok(if jumped { wire_len } else { wire_len + 1 });
            }
            1..=63 => {
                let end = position + 1 + usize::from(length);
                if jumped && end > pointer_limit {
                    return Err(NameError::PointerNotBackwards);
                }
                if message.get(position + 1..end).is_none() {
                    return Err(NameError::Truncated);
                }
                expanded_len += 1 + usize::from(length);
                if expanded_len > MAX_NAME_LEN {
                    return Err(NameError::NameTooLong);
                }
                if !jumped {
                    wire_len += 1 + usize::from(length);
                }
                position = end;
            }
            0xc0..=0xff => {
                if jumped && position + 2 > pointer_limit {
                    return Err(NameError::PointerNotBackwards);
                }
                let low = *message.get(position + 1).ok_or(NameError::Truncated)?;
                let target = usize::from(length & 0x3f) << 8 | usize::from(low);
                // RFC 1035 §4.1.4: compression pointers refer to a prior occurrence.
                if target >= position {
                    return Err(NameError::PointerNotBackwards);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(NameError::PointerLimit);
                }
                if !jumped {
                    wire_len += 2;
                    jumped = true;
                }
                pointer_limit = position;
                position = target;
            }
            _ => return Err(NameError::InvalidLabelType),
        }
    }
}

fn check_uncompressed(wire: &[u8]) -> Result<(), NameError> {
    if wire.len() > MAX_NAME_LEN {
        return Err(NameError::NameTooLong);
    }
    let mut position = 0;
    loop {
        let length = *wire.get(position).ok_or(NameError::Truncated)?;
        if length == 0 {
            return (position + 1 == wire.len())
                .then_some(())
                .ok_or(NameError::InvalidLabelType);
        }
        if usize::from(length) > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong);
        }
        position += 1 + usize::from(length);
        if position > wire.len() {
            return Err(NameError::Truncated);
        }
    }
}

fn push_label(wire: &mut Vec<u8>, label: &[u8]) -> Result<(), NameError> {
    if label.is_empty() {
        return Err(NameError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(NameError::LabelTooLong);
    }
    wire.push(label.len() as u8);
    wire.extend_from_slice(label);
    Ok(())
}

fn labels(wire: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut position = 0;
    std::iter::from_fn(move || {
        let length = *wire.get(position)? as usize;
        if length == 0 {
            return None;
        }
        let label = wire.get(position + 1..position + 1 + length)?;
        position += 1 + length;
        Some(label)
    })
}

fn label_offsets(wire: &[u8]) -> ([usize; MAX_LABELS], usize) {
    let mut offsets = [0; MAX_LABELS];
    let mut count = 0;
    let mut position = 0;
    while wire[position] != 0 {
        offsets[count] = position;
        count += 1;
        position += 1 + usize::from(wire[position]);
    }
    (offsets, count)
}

fn label_at(wire: &[u8], offset: usize) -> &[u8] {
    &wire[offset + 1..offset + 1 + usize::from(wire[offset])]
}

fn equal_label(left: &[u8], right: &[u8]) -> bool {
    // RFC 4343 §3: ASCII letters in DNS labels compare case-insensitively.
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| ascii_lower(*left) == ascii_lower(*right))
}

fn equal_labels<'a>(
    mut left: impl Iterator<Item = &'a [u8]>,
    mut right: impl Iterator<Item = &'a [u8]>,
) -> bool {
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) if equal_label(left, right) => {}
            _ => return false,
        }
    }
}

fn canonical_label_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.iter()
        .map(|byte| ascii_lower(*byte))
        .cmp(right.iter().map(|byte| ascii_lower(*byte)))
}

const fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte | 0x20
    } else {
        byte
    }
}

fn write_presentation<'a>(
    output: &mut impl Write,
    labels: impl Iterator<Item = &'a [u8]>,
    canonical: bool,
) -> fmt::Result {
    // RFC 4343 §2.1: escape dots and non-printing label octets in presentation form.
    let mut first = true;
    for label in labels {
        if !first {
            output.write_char('.')?;
        }
        first = false;
        for byte in label {
            let byte = if canonical { ascii_lower(*byte) } else { *byte };
            if matches!(
                byte,
                b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\'
            ) {
                write!(output, "\\{}", char::from(byte))?;
            } else if (b'!'..=b'~').contains(&byte) {
                output.write_char(char::from(byte))?;
            } else {
                write!(output, "\\{byte:03}")?;
            }
        }
    }
    output.write_char('.')
}
