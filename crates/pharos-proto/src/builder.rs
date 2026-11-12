use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{Class, NameRef, ResponseOpt, Type};

const MIN_MESSAGE_SIZE: usize = 512;
const COMPRESSION_SLOTS: usize = 128;

/// Storage used by a DNS Message builder.
pub trait MessageBuffer: Deref<Target = [u8]> + DerefMut {
    fn clear_buffer(&mut self);
    fn append_buffer(&mut self, bytes: &[u8]);
    fn truncate_buffer(&mut self, len: usize);
    fn max_capacity(&self) -> usize;
}

impl MessageBuffer for Vec<u8> {
    fn clear_buffer(&mut self) {
        self.clear();
    }
    fn append_buffer(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn truncate_buffer(&mut self, len: usize) {
        self.truncate(len);
    }
    fn max_capacity(&self) -> usize {
        usize::MAX
    }
}

/// Fixed caller-provided storage for a Message builder.
pub struct FixedBuffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}
impl<'a> FixedBuffer<'a> {
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }
}
impl Deref for FixedBuffer<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl DerefMut for FixedBuffer<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}
impl MessageBuffer for FixedBuffer<'_> {
    fn clear_buffer(&mut self) {
        self.len = 0;
    }
    fn append_buffer(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }
    fn truncate_buffer(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
    fn max_capacity(&self) -> usize {
        self.bytes.len()
    }
}

/// A failure to construct a DNS Message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// The maximum Message size exceeds 65535 octets.
    InvalidMaxSize,
    /// A section was added after a later section.
    SectionOrder,
    /// A section already contains 65535 entries.
    CountOverflow,
    /// RDATA cannot be represented by the 16-bit RDLENGTH field.
    RdataTooLong,
    /// The Message size limit was reached while writing RDATA.
    SizeLimit,
    /// An RDATA writer rejected its input.
    InvalidRdata,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMaxSize => "invalid maximum DNS Message size",
            Self::SectionOrder => "DNS sections are out of order",
            Self::CountOverflow => "DNS section count overflow",
            Self::RdataTooLong => "RDATA exceeds 65535 octets",
            Self::SizeLimit => "DNS Message size limit reached",
            Self::InvalidRdata => "invalid RDATA",
        })
    }
}

impl std::error::Error for BuildError {}

/// The section containing a resource record, in wire order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Section {
    /// The Answer section.
    Answer,
    /// The Authority section.
    Authority,
    /// The Additional section.
    Additional,
}

impl Section {
    const fn index(self) -> usize {
        match self {
            Self::Answer => 1,
            Self::Authority => 2,
            Self::Additional => 3,
        }
    }
}

/// An allocation-free Message builder apart from growth of the caller's buffer.
///
/// Entries must be added in Question, Answer, Authority, Additional order.
/// A `false` result means the size limit was reached and the builder has stopped.
/// The first entry that does not fit is rolled back and TC is set.
pub struct MessageBuilder<'a, B: MessageBuffer = Vec<u8>> {
    wire: &'a mut B,
    max_size: usize,
    reserved: usize,
    counts: [u16; 4],
    section: usize,
    stopped: bool,
    offsets: [u16; COMPRESSION_SLOTS],
    offset_count: usize,
}

impl<'a, B: MessageBuffer> MessageBuilder<'a, B> {
    /// Clears `wire`, retaining its capacity, and writes a header with raw flags.
    /// Invalid maximum sizes leave the buffer unchanged. The caller must encode
    /// opcode, RCODE and other flags in their respective header bit positions.
    /// Maximum sizes below 512 octets are treated as 512.
    pub fn new(wire: &'a mut B, max_size: usize, id: u16, flags: u16) -> Result<Self, BuildError> {
        if max_size > usize::from(u16::MAX) || max_size.max(MIN_MESSAGE_SIZE) > wire.max_capacity()
        {
            return Err(BuildError::InvalidMaxSize);
        }
        wire.clear_buffer();
        // RFC 1035 §4.1.1: the header starts with ID, flags, and four section counts.
        wire.append_buffer(&id.to_be_bytes());
        wire.append_buffer(&flags.to_be_bytes());
        wire.append_buffer(&[0; 8]);
        Ok(Self {
            wire,
            max_size: max_size.max(MIN_MESSAGE_SIZE),
            reserved: 0,
            counts: [0; 4],
            section: 0,
            stopped: false,
            offsets: [0; COMPRESSION_SLOTS],
            offset_count: 0,
        })
    }

    /// Reserves additional space for an OPT appended when finishing.
    /// Returns an error without changing the reservation if the remaining space is too small.
    pub fn reserve(&mut self, size: usize) -> Result<(), BuildError> {
        if size > self.max_size - self.reserved - self.wire.len() {
            return Err(BuildError::SizeLimit);
        }
        self.reserved += size;
        Ok(())
    }

    /// Reserves the exact space needed for a Response OPT before adding records.
    pub fn reserve_response_opt(&mut self, opt: &ResponseOpt<'_, '_>) -> Result<(), BuildError> {
        self.reserve(opt.wire_len())
    }

    /// Adds a Question. If it cannot fit, it is rolled back, TC is set, and writing stops.
    pub fn question(
        &mut self,
        name: NameRef<'_>,
        qtype: Type,
        class: Class,
    ) -> Result<bool, BuildError> {
        if self.stopped {
            return Ok(false);
        }
        if self.section != 0 {
            return Err(BuildError::SectionOrder);
        }
        self.check_count(0)?;
        let start = self.wire.len();
        let slots = self.offset_count;
        // RFC 1035 §4.1.2: each question contains QNAME, QTYPE, and QCLASS.
        let result = self
            .write_name(name)
            .and_then(|()| self.write_bytes(&qtype.0.to_be_bytes()))
            .and_then(|()| self.write_bytes(&class.0.to_be_bytes()));
        self.finish_entry(0, start, slots, result)
    }

    /// Adds a record with raw RDATA. Embedded compression pointers must already
    /// refer to valid offsets in this Message; use `record_with` for domain names.
    pub fn record(
        &mut self,
        section: Section,
        name: NameRef<'_>,
        rtype: Type,
        class: Class,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<bool, BuildError> {
        if self.stopped {
            return Ok(false);
        }
        if rdata.len() > usize::from(u16::MAX) {
            return Err(BuildError::RdataTooLong);
        }
        self.record_with(section, name, rtype, class, ttl, |writer| {
            writer.write_bytes(rdata)
        })
    }

    /// Adds a record whose RDATA is written through a bounded, compression-aware hook.
    /// A hook error rolls back the whole record. `SizeLimit` instead reports `Ok(false)`.
    pub fn record_with(
        &mut self,
        section: Section,
        name: NameRef<'_>,
        rtype: Type,
        class: Class,
        ttl: u32,
        write: impl FnOnce(&mut RdataWriter<'_, 'a, B>) -> Result<(), BuildError>,
    ) -> Result<bool, BuildError> {
        if self.stopped {
            return Ok(false);
        }
        let index = section.index();
        if index < self.section {
            return Err(BuildError::SectionOrder);
        }
        self.check_count(index)?;
        let start = self.wire.len();
        let slots = self.offset_count;
        // RFC 1035 §4.1.3: each RR contains NAME, TYPE, CLASS, TTL, RDLENGTH, and RDATA.
        let result = (|| {
            self.write_name(name)?;
            self.write_bytes(&rtype.0.to_be_bytes())?;
            self.write_bytes(&class.0.to_be_bytes())?;
            self.write_bytes(&ttl.to_be_bytes())?;
            let length_offset = self.wire.len();
            self.write_bytes(&[0, 0])?;
            let rdata_start = self.wire.len();
            write(&mut RdataWriter {
                builder: self,
                compress: true,
            })?;
            let length = u16::try_from(self.wire.len() - rdata_start)
                .map_err(|_| BuildError::RdataTooLong)?;
            self.wire[length_offset..length_offset + 2].copy_from_slice(&length.to_be_bytes());
            Ok(())
        })();
        self.finish_entry(index, start, slots, result)
    }

    /// Appends one pre-encoded OPT record from the reserved space and finishes.
    /// The record must have an uncompressed root owner and a complete RDATA field.
    /// On error, the buffer contains the completed Message without the OPT.
    pub fn finish_with_opt(mut self, opt: &[u8]) -> Result<&'a mut B, BuildError> {
        let error = if opt.len() > self.reserved {
            Some(BuildError::SizeLimit)
        } else if opt.len() < 11
            || opt[0..3] != [0, 0, 41]
            || usize::from(u16::from_be_bytes([opt[9], opt[10]])) != opt.len() - 11
        {
            Some(BuildError::InvalidRdata)
        } else {
            self.check_count(3).err()
        };
        if let Some(error) = error {
            let _ = self.finish();
            return Err(error);
        }
        self.wire.append_buffer(opt);
        self.counts[3] += 1;
        Ok(self.finish())
    }

    /// Completes the header and returns the caller's buffer.
    #[must_use]
    pub fn finish(self) -> &'a mut B {
        for (index, count) in self.counts.iter().enumerate() {
            self.wire[4 + index * 2..6 + index * 2].copy_from_slice(&count.to_be_bytes());
        }
        self.wire
    }

    fn check_count(&self, index: usize) -> Result<(), BuildError> {
        if self.counts[index] == u16::MAX {
            Err(BuildError::CountOverflow)
        } else {
            Ok(())
        }
    }

    fn finish_entry(
        &mut self,
        index: usize,
        start: usize,
        slots: usize,
        result: Result<(), BuildError>,
    ) -> Result<bool, BuildError> {
        match result {
            Ok(()) => {
                self.counts[index] += 1;
                self.section = index;
                Ok(true)
            }
            Err(error) => {
                self.wire.truncate_buffer(start);
                self.offset_count = slots;
                if error != BuildError::SizeLimit {
                    return Err(error);
                }
                // RFC 1035 §4.1.1: TC marks a message truncated by the transmission limit.
                self.wire[2] |= 0x02;
                self.stopped = true;
                Ok(false)
            }
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), BuildError> {
        if bytes.len() > self.max_size - self.reserved - self.wire.len() {
            return Err(BuildError::SizeLimit);
        }
        self.wire.append_buffer(bytes);
        Ok(())
    }

    fn write_name(&mut self, name: NameRef<'_>) -> Result<(), BuildError> {
        self.write_name_with_compression(name, true)
    }

    fn write_name_with_compression(
        &mut self,
        name: NameRef<'_>,
        compress: bool,
    ) -> Result<(), BuildError> {
        for (index, label) in name.labels().enumerate() {
            let pointer = self.offsets[..self.offset_count]
                .iter()
                .copied()
                .find(|offset| {
                    let offset = usize::from(*offset);
                    offset < self.wire.len()
                        && NameRef::parse(self.wire, offset)
                            .is_ok_and(|stored| stored.labels().eq(name.labels().skip(index)))
                });
            // RFC 1035 §4.1.4: a pointer has two leading one bits and a 14-bit offset.
            if compress && let Some(offset) = pointer {
                return self.write_bytes(&(0xc000 | offset).to_be_bytes());
            }
            if pointer.is_none()
                && self.wire.len() < 0x4000
                && self.offset_count < COMPRESSION_SLOTS
            {
                self.offsets[self.offset_count] = self.wire.len() as u16;
                self.offset_count += 1;
            }
            self.write_bytes(&[label.len() as u8])?;
            self.write_bytes(label)?;
        }
        self.write_bytes(&[0])
    }
}

impl<'a> MessageBuilder<'a, Vec<u8>> {
    /// Appends the reserved Response OPT even if earlier records were truncated.
    pub fn finish_with_response_opt(
        mut self,
        opt: &ResponseOpt<'_, '_>,
    ) -> Result<&'a mut Vec<u8>, BuildError> {
        let error = if opt.wire_len() > self.reserved {
            Some(BuildError::SizeLimit)
        } else {
            self.check_count(3).err()
        };
        if let Some(error) = error {
            let _ = self.finish();
            return Err(error);
        }
        if let Err(error) = opt.encode(self.wire) {
            let _ = self.finish();
            return Err(error);
        }
        self.counts[3] += 1;
        Ok(self.finish())
    }
}

/// A bounded RDATA writer that can encode compressed names in the Message.
pub struct RdataWriter<'b, 'a, B: MessageBuffer = Vec<u8>> {
    builder: &'b mut MessageBuilder<'a, B>,
    compress: bool,
}

impl<B: MessageBuffer> RdataWriter<'_, '_, B> {
    /// Disable compression for subsequent RDATA names in this record.
    pub fn disable_compression(&mut self) {
        self.compress = false;
    }
    /// Writes literal bytes; callers are responsible for their RDATA format.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), BuildError> {
        self.builder.write_bytes(bytes)
    }

    /// Writes a name, compressing against earlier Message names when possible.
    ///
    /// This low-level hook does not know the RR type. Call it only when that
    /// type permits compression in RDATA (RFC 3597); otherwise use
    /// [`Self::write_uncompressed_name`]. Unknown RDATA must remain opaque and
    /// should be written with [`Self::write_bytes`].
    pub fn write_name(&mut self, name: NameRef<'_>) -> Result<(), BuildError> {
        self.builder
            .write_name_with_compression(name, self.compress)
    }

    /// Writes literal labels while registering them as future compression targets.
    pub fn write_uncompressed_name(&mut self, name: NameRef<'_>) -> Result<(), BuildError> {
        self.builder.write_name_with_compression(name, false)
    }
}
