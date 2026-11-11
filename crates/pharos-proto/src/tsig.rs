use std::fmt;

use aws_lc_rs::{constant_time, hmac as aws_hmac};
use hmac::{Hmac, Mac};
use md5::Md5;

use crate::{Class, Message, Name, NameRef, NameWirePart, Rdata, Type};

/// TSIG algorithms supported for compatibility with CoreDNS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsigAlgorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl TsigAlgorithm {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Md5 => b"\x08hmac-md5\x07sig-alg\x03reg\x03int\0",
            Self::Sha1 => b"\x09hmac-sha1\0",
            Self::Sha224 => b"\x0bhmac-sha224\0",
            Self::Sha256 => b"\x0bhmac-sha256\0",
            Self::Sha384 => b"\x0bhmac-sha384\0",
            Self::Sha512 => b"\x0bhmac-sha512\0",
        }
    }

    fn len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// TSIG verification and encoding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsigError {
    /// Malformed Message, TSIG or prohibited MAC length (FORMERR).
    Format,
    /// Unknown key or algorithm (BADKEY).
    BadKey,
    /// Incorrect MAC (BADSIG).
    BadSig,
    /// Signature outside its validity interval (BADTIME).
    BadTime,
    /// MAC shorter than local policy (BADTRUNC).
    BadTrunc,
}
impl fmt::Display for TsigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TsigError {}

// Avoid heap allocation on the signing path for the larger SHA context.
#[allow(clippy::large_enum_variant)]
enum KeyMaterial {
    Md5(Hmac<Md5>),
    Sha(aws_hmac::Key),
}

// Avoid heap allocation on the signing path for the larger SHA context.
#[allow(clippy::large_enum_variant)]
enum Digest {
    Md5(Hmac<Md5>),
    Sha(aws_hmac::Context),
}
impl Digest {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md5(context) => context.update(bytes),
            Self::Sha(context) => context.update(bytes),
        }
    }
    fn finish(self) -> ([u8; 64], usize) {
        let mut output = [0; 64];
        let len = match self {
            Self::Md5(context) => {
                let tag = context.finalize().into_bytes();
                output[..tag.len()].copy_from_slice(&tag);
                tag.len()
            }
            Self::Sha(context) => {
                let tag = context.sign();
                output[..tag.as_ref().len()].copy_from_slice(tag.as_ref());
                tag.as_ref().len()
            }
        };
        (output, len)
    }
}

/// A configured TSIG key. Secret material is not included in debug output.
pub struct TsigKey {
    name: Name,
    algorithm: TsigAlgorithm,
    key: KeyMaterial,
}
impl TsigKey {
    #[must_use]
    pub fn new(name: Name, algorithm: TsigAlgorithm, secret: &[u8]) -> Self {
        // RFC 8945 §6: TSIG algorithm names select the corresponding HMAC.
        let key = match algorithm {
            TsigAlgorithm::Md5 => KeyMaterial::Md5(
                Hmac::<Md5>::new_from_slice(secret).expect("HMAC accepts any key length"),
            ),
            _ => KeyMaterial::Sha(aws_hmac::Key::new(
                match algorithm {
                    TsigAlgorithm::Sha1 => aws_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                    TsigAlgorithm::Sha224 => aws_hmac::HMAC_SHA224,
                    TsigAlgorithm::Sha256 => aws_hmac::HMAC_SHA256,
                    TsigAlgorithm::Sha384 => aws_hmac::HMAC_SHA384,
                    TsigAlgorithm::Sha512 => aws_hmac::HMAC_SHA512,
                    TsigAlgorithm::Md5 => unreachable!(),
                },
                secret,
            )),
        };
        Self {
            name,
            algorithm,
            key,
        }
    }

    fn digest(&self) -> Digest {
        match &self.key {
            KeyMaterial::Md5(key) => Digest::Md5(key.clone()),
            KeyMaterial::Sha(key) => Digest::Sha(aws_hmac::Context::with_key(key)),
        }
    }

    /// Appends a full-length TSIG to a Message, chaining the Query MAC for a Response.
    /// Set a Response's header ID to the original Query ID before signing.
    pub fn sign(
        &self,
        wire: &mut Vec<u8>,
        time: u64,
        fudge: u16,
        prior_mac: Option<&[u8]>,
    ) -> Result<(), TsigError> {
        self.sign_truncated(wire, time, fudge, prior_mac, self.algorithm.len())
    }

    /// Appends a TSIG with an RFC-permitted MAC length.
    /// For a Response, set its header ID to the original Query ID and pass its verified MAC.
    pub fn sign_truncated(
        &self,
        wire: &mut Vec<u8>,
        time: u64,
        fudge: u16,
        prior_mac: Option<&[u8]>,
        mac_len: usize,
    ) -> Result<(), TsigError> {
        // RFC 8945 §4.3.1: a Response MAC must include the validated Query MAC.
        if wire.get(2).is_some_and(|flags| flags & 0x80 != 0)
            && prior_mac.is_none_or(|mac| {
                mac.len() < 10.max(self.algorithm.len() / 2) || mac.len() > self.algorithm.len()
            })
        {
            return Err(TsigError::Format);
        }
        // RFC 8945 §5.2.2.1: truncated MACs have a mandatory minimum size.
        if mac_len > self.algorithm.len() || mac_len < 10.max(self.algorithm.len() / 2) {
            return Err(TsigError::Format);
        }
        self.validate_sign(wire, time, mac_len)?;
        let mut digest = self.digest();
        if let Some(mac) = prior_mac {
            let len = u16::try_from(mac.len()).map_err(|_| TsigError::Format)?;
            digest.update(&len.to_be_bytes());
            digest.update(mac);
        }
        // RFC 8945 §4.3: hash the Message before adding TSIG, then its variables.
        digest.update(wire);
        let owner = NameRef::parse(self.name.as_wire(), 0).expect("valid key name");
        let algorithm = NameRef::parse(self.algorithm.name(), 0).expect("valid algorithm name");
        variables(&mut digest, owner, algorithm, time, fudge, 0, &[]);
        let (mac, _) = digest.finish();
        self.append(wire, time, fudge, &mac[..mac_len]);
        Ok(())
    }

    fn validate_sign(&self, wire: &[u8], time: u64, mac_len: usize) -> Result<(), TsigError> {
        let msg = Message::parse(wire).map_err(|_| TsigError::Format)?;
        // RFC 8945 §4.2 and RFC 1035 §4.1.1: time and section counts have fixed widths.
        if message_end(&msg) != wire.len()
            || time >= (1 << 48)
            || msg.additional_count() == u16::MAX
            || msg
                .answers()
                .chain(msg.authorities())
                .chain(msg.additionals())
                .any(|rr| rr.rtype == Type::TSIG)
        {
            return Err(TsigError::Format);
        }
        let size = self.name.as_wire().len() + 10 + self.algorithm.name().len() + 16 + mac_len;
        if wire.len() + size > usize::from(u16::MAX) {
            return Err(TsigError::Format);
        }
        Ok(())
    }

    fn append(&self, wire: &mut Vec<u8>, time: u64, fudge: u16, mac: &[u8]) {
        // RFC 8945 §4.2: append the TSIG fields in wire order.
        let id = [wire[0], wire[1]];
        let count = u16::from_be_bytes([wire[10], wire[11]]) + 1;
        wire.extend_from_slice(self.name.as_wire());
        wire.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
        let rdata_len = self.algorithm.name().len() + 16 + mac.len();
        wire.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        wire.extend_from_slice(self.algorithm.name());
        wire.extend_from_slice(&time.to_be_bytes()[2..]);
        wire.extend_from_slice(&fudge.to_be_bytes());
        wire.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        wire.extend_from_slice(mac);
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&[0, 0, 0, 0]);
        wire[10..12].copy_from_slice(&count.to_be_bytes());
    }

    /// Construct a NOTAUTH Response to a failed TSIG Query.
    /// The Query is verified here so an unauthenticated MAC is never signed.
    pub fn sign_error_response(
        &self,
        response: &mut Vec<u8>,
        query: &[u8],
        now: u64,
        minimum_mac: usize,
    ) -> Result<Option<TsigError>, TsigError> {
        let query_tsig = parse(query)?;
        if query[2] & 0x80 != 0 {
            return Err(TsigError::Format);
        }
        let failure = match self.verify(query, now, None, minimum_mac) {
            Err(
                error @ (TsigError::BadKey
                | TsigError::BadSig
                | TsigError::BadTime
                | TsigError::BadTrunc),
            ) => error,
            Ok(_) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.validate_sign(response, now, 0)?;
        // RFC 8945 §4.2: the server time is an unsigned 48-bit integer.
        if now >= 1 << 48 {
            return Err(TsigError::Format);
        }
        let code: u16 = match failure {
            TsigError::BadSig => 16,
            TsigError::BadKey => 17,
            TsigError::BadTime => 18,
            TsigError::BadTrunc => 22,
            TsigError::Format => unreachable!(),
        };
        // RFC 8945 §5.3.2: only an authenticated Query MAC may be chained in an error Response.
        let authenticated = matches!(failure, TsigError::BadTime | TsigError::BadTrunc);
        let time = if failure == TsigError::BadTime {
            query_tsig.time_signed
        } else if authenticated {
            now
        } else {
            0
        };
        let server_time = now.to_be_bytes();
        let other = if failure == TsigError::BadTime {
            &server_time[2..]
        } else {
            &[]
        };
        let owner_len: usize = query_tsig
            .owner
            .labels()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1;
        let algorithm_len: usize = query_tsig
            .algorithm
            .labels()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1;
        let mac_len = if authenticated {
            self.algorithm.len()
        } else {
            0
        };
        if response.len() + owner_len + 10 + algorithm_len + 16 + mac_len + other.len()
            > usize::from(u16::MAX)
        {
            return Err(TsigError::Format);
        }
        response[3] = (response[3] & 0xf0) | 9;
        let mut mac = [0; 64];
        if authenticated {
            let mut digest = self.digest();
            digest.update(&(query_tsig.mac.len() as u16).to_be_bytes());
            digest.update(query_tsig.mac);
            digest.update(&query_tsig.original_id.to_be_bytes());
            digest.update(&response[2..]);
            variables(
                &mut digest,
                query_tsig.owner,
                query_tsig.algorithm,
                time,
                query_tsig.fudge,
                code,
                other,
            );
            (mac, _) = digest.finish();
        }
        let count = u16::from_be_bytes([response[10], response[11]]) + 1;
        write_name(response, query_tsig.owner);
        response.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
        response.extend_from_slice(
            &((algorithm_len + 16 + mac_len + other.len()) as u16).to_be_bytes(),
        );
        write_name(response, query_tsig.algorithm);
        response.extend_from_slice(&time.to_be_bytes()[2..]);
        response.extend_from_slice(&query_tsig.fudge.to_be_bytes());
        response.extend_from_slice(&(mac_len as u16).to_be_bytes());
        response.extend_from_slice(&mac[..mac_len]);
        response.extend_from_slice(&query_tsig.original_id.to_be_bytes());
        response.extend_from_slice(&code.to_be_bytes());
        response.extend_from_slice(&(other.len() as u16).to_be_bytes());
        response.extend_from_slice(other);
        response[10..12].copy_from_slice(&count.to_be_bytes());
        Ok(Some(failure))
    }

    /// Verifies a signed Message, requiring the Query MAC for a Response.
    /// `minimum_mac` is the local truncation policy in octets (0 uses RFC minimum).
    pub fn verify<'a>(
        &self,
        wire: &'a [u8],
        now: u64,
        prior_mac: Option<&[u8]>,
        minimum_mac: usize,
    ) -> Result<TsigRecord<'a>, TsigError> {
        let tsig = parse(wire)?;
        // RFC 8945 §4.3.1: a Response MAC must include the validated Query MAC.
        if wire[2] & 0x80 != 0
            && prior_mac.is_none_or(|mac| {
                mac.len() < 10.max(self.algorithm.len() / 2) || mac.len() > self.algorithm.len()
            })
        {
            return Err(TsigError::Format);
        }
        // RFC 8945 §4.2: the Error field in a Query must be zero.
        if wire[2] & 0x80 == 0 && tsig.error != 0 {
            return Err(TsigError::Format);
        }
        // RFC 8945 §5.2.1: identify the key and algorithm before checking the MAC.
        if tsig.owner != self.name
            || tsig.algorithm != NameRef::parse(self.algorithm.name(), 0).expect("algorithm name")
        {
            return Err(TsigError::BadKey);
        }
        let len = tsig.mac.len();
        // RFC 8945 §5.2.2.1: reject MACs shorter than 10 octets or half the hash.
        if len > self.algorithm.len() || len < 10.max(self.algorithm.len() / 2) {
            return Err(TsigError::Format);
        }
        let mut digest = self.digest();
        if let Some(mac) = prior_mac {
            let n = u16::try_from(mac.len()).map_err(|_| TsigError::Format)?;
            digest.update(&n.to_be_bytes());
            digest.update(mac);
        }
        // RFC 8945 §4.3.2: remove TSIG, decrement ARCOUNT and restore the original ID.
        digest.update(&tsig.original_id.to_be_bytes());
        digest.update(&wire[2..10]);
        let count = u16::from_be_bytes([wire[10], wire[11]]) - 1;
        digest.update(&count.to_be_bytes());
        digest.update(&wire[12..tsig.start]);
        variables(
            &mut digest,
            tsig.owner,
            tsig.algorithm,
            tsig.time_signed,
            tsig.fudge,
            tsig.error,
            tsig.other,
        );
        let (tag, _) = digest.finish();
        if constant_time::verify_slices_are_equal(&tag[..len], tsig.mac).is_err() {
            return Err(TsigError::BadSig);
        }
        // RFC 8945 §5.2.3: check time only after authenticating the MAC.
        if now.abs_diff(tsig.time_signed) > u64::from(tsig.fudge) {
            return Err(TsigError::BadTime);
        }
        if len < minimum_mac {
            return Err(TsigError::BadTrunc);
        }
        Ok(tsig)
    }
}

/// Running authentication state for a multi-Message Response.
/// The first Message and the final Message must be signed.
pub struct TsigStream<'a> {
    key: &'a TsigKey,
    query_mac: &'a [u8],
    digest: Option<Digest>,
    unsigned: usize,
    last_time: Option<u64>,
    failed: bool,
}

impl<'a> TsigStream<'a> {
    #[must_use]
    pub fn new(key: &'a TsigKey, query_mac: &'a [u8]) -> Self {
        Self {
            key,
            query_mac,
            digest: None,
            unsigned: 0,
            last_time: None,
            failed: false,
        }
    }

    fn chain(&mut self, mac: &[u8], time: u64) {
        // RFC 8945 §5.3.1: each running MAC starts with the previous MAC and its length.
        let mut digest = self.key.digest();
        digest.update(&(mac.len() as u16).to_be_bytes());
        digest.update(mac);
        self.digest = Some(digest);
        self.unsigned = 0;
        self.last_time = Some(time);
    }

    /// Add an unsigned intermediate Response from a legacy stream.
    /// RFC 8945 requires senders to sign all Responses; use this only for legacy interoperability.
    pub fn add_unsigned(&mut self, wire: &[u8]) -> Result<(), TsigError> {
        let message = Message::parse(wire).map_err(|_| TsigError::Format)?;
        if self.failed
            || self.digest.is_none()
            || self.unsigned >= 99
            || message_end(&message) != wire.len()
            || message
                .answers()
                .chain(message.authorities())
                .chain(message.additionals())
                .any(|rr| rr.rtype == Type::TSIG)
        {
            return Err(TsigError::Format);
        }
        // RFC 8945 §5.3.1: hash up to 99 unsigned intermediary Messages in order.
        self.digest.as_mut().expect("checked above").update(wire);
        self.unsigned += 1;
        Ok(())
    }

    /// Sign one Response Message, appending TSIG to the caller's buffer.
    /// Set its header ID to the original Query ID before signing.
    pub fn sign(&mut self, wire: &mut Vec<u8>, time: u64, fudge: u16) -> Result<(), TsigError> {
        if self.failed {
            return Err(TsigError::Format);
        }
        if self.digest.is_none() {
            self.key.sign(wire, time, fudge, Some(self.query_mac))?;
            let tsig = parse(wire)?;
            self.chain(tsig.mac, time);
            return Ok(());
        }
        if self.last_time.is_some_and(|last| time < last) {
            return Err(TsigError::BadTime);
        }
        self.key
            .validate_sign(wire, time, self.key.algorithm.len())?;
        let mut digest = self.digest.take().expect("checked above");
        // RFC 8945 §5.3.1: subsequent Messages hash only the running MAC, Message and timers.
        digest.update(wire);
        digest.update(&time.to_be_bytes()[2..]);
        digest.update(&fudge.to_be_bytes());
        let (mac, len) = digest.finish();
        self.key.append(wire, time, fudge, &mac[..len]);
        self.chain(&mac[..len], time);
        Ok(())
    }

    /// Verify one Response, accepting up to 99 unsigned intermediate Messages.
    pub fn verify<'m>(
        &mut self,
        wire: &'m [u8],
        now: u64,
        minimum_mac: usize,
    ) -> Result<Option<TsigRecord<'m>>, TsigError> {
        if self.failed {
            return Err(TsigError::Format);
        }
        let result = self.verify_inner(wire, now, minimum_mac);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn verify_inner<'m>(
        &mut self,
        wire: &'m [u8],
        now: u64,
        minimum_mac: usize,
    ) -> Result<Option<TsigRecord<'m>>, TsigError> {
        let message = Message::parse(wire).map_err(|_| TsigError::Format)?;
        if message_end(&message) != wire.len() {
            return Err(TsigError::Format);
        }
        let has_tsig = message
            .answers()
            .chain(message.authorities())
            .chain(message.additionals())
            .any(|rr| rr.rtype == Type::TSIG);
        if !has_tsig {
            self.add_unsigned(wire)?;
            return Ok(None);
        }
        if self.digest.is_none() {
            let tsig = self
                .key
                .verify(wire, now, Some(self.query_mac), minimum_mac)?;
            self.chain(tsig.mac, tsig.time_signed);
            return Ok(Some(tsig));
        }
        let tsig = parse(wire)?;
        // RFC 8945 §5.3.1: later MACs omit Error and Other Data, so reject them.
        if tsig.error != 0 || !tsig.other.is_empty() {
            return Err(TsigError::Format);
        }
        if tsig.owner != self.key.name
            || tsig.algorithm
                != NameRef::parse(self.key.algorithm.name(), 0).expect("algorithm name")
        {
            return Err(TsigError::BadKey);
        }
        let len = tsig.mac.len();
        // RFC 8945 §5.2.2.1: enforce the permitted MAC length in every stream Message.
        if len > self.key.algorithm.len() || len < 10.max(self.key.algorithm.len() / 2) {
            return Err(TsigError::Format);
        }
        let mut digest = self.digest.take().expect("checked above");
        digest.update(&tsig.original_id.to_be_bytes());
        digest.update(&wire[2..10]);
        let count = u16::from_be_bytes([wire[10], wire[11]]) - 1;
        digest.update(&count.to_be_bytes());
        digest.update(&wire[12..tsig.start]);
        digest.update(&tsig.time_signed.to_be_bytes()[2..]);
        digest.update(&tsig.fudge.to_be_bytes());
        let (tag, _) = digest.finish();
        if constant_time::verify_slices_are_equal(&tag[..len], tsig.mac).is_err() {
            return Err(TsigError::BadSig);
        }
        // RFC 8945 §5.3.1: successive signed stream timestamps do not decrease.
        if now.abs_diff(tsig.time_signed) > u64::from(tsig.fudge)
            || self.last_time.is_some_and(|last| tsig.time_signed < last)
        {
            return Err(TsigError::BadTime);
        }
        if len < minimum_mac {
            return Err(TsigError::BadTrunc);
        }
        self.chain(tsig.mac, tsig.time_signed);
        Ok(Some(tsig))
    }

    /// Reject a stream with no signed Response or an unsigned final Message.
    pub fn finish(&self) -> Result<(), TsigError> {
        if self.failed || self.digest.is_none() || self.unsigned != 0 {
            Err(TsigError::Format)
        } else {
            Ok(())
        }
    }
}

/// Parsed TSIG fields borrowing the original Message.
#[derive(Debug)]
pub struct TsigRecord<'a> {
    pub owner: NameRef<'a>,
    pub algorithm: NameRef<'a>,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: &'a [u8],
    pub original_id: u16,
    pub error: u16,
    pub other: &'a [u8],
    start: usize,
}

impl<'a> TsigRecord<'a> {
    /// Parse a TSIG without authenticating it; do not trust its fields yet.
    pub fn parse(wire: &'a [u8]) -> Result<Self, TsigError> {
        parse(wire)
    }
}

fn write_name(output: &mut Vec<u8>, name: NameRef<'_>) {
    for label in name.labels() {
        output.push(label.len() as u8);
        output.extend_from_slice(label);
    }
    output.push(0);
}

fn parse(wire: &[u8]) -> Result<TsigRecord<'_>, TsigError> {
    let msg = Message::parse(wire).map_err(|_| TsigError::Format)?;
    // RFC 8945 §5.2: exactly one TSIG is permitted, last in Additional.
    if msg
        .answers()
        .chain(msg.authorities())
        .any(|rr| rr.rtype == Type::TSIG)
    {
        return Err(TsigError::Format);
    }
    let mut found = None;
    for rr in msg.additionals() {
        if found.is_some() {
            return Err(TsigError::Format);
        }
        if rr.rtype != Type::TSIG {
            continue;
        }
        if rr.class != Class::ANY || rr.ttl != 0 || rr.rdata_offset + rr.rdata.len() != wire.len() {
            return Err(TsigError::Format);
        }
        let Rdata::Tsig {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        } = rr.data().map_err(|_| TsigError::Format)?
        else {
            return Err(TsigError::Format);
        };
        // RFC 8945 §4.2: the algorithm name MUST NOT be compressed.
        if algorithm
            .wire_parts()
            .any(|part| matches!(part, NameWirePart::Pointer { .. }))
        {
            return Err(TsigError::Format);
        }
        found = Some(TsigRecord {
            owner: rr.name,
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
            start: rr.name.offset(),
        });
    }
    found.ok_or(TsigError::Format)
}

fn message_end(message: &Message<'_>) -> usize {
    // RFC 1035 §4.1: sections occupy the complete encoded Message in order.
    if let Some(record) = message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .last()
    {
        record.rdata_offset + record.rdata.len()
    } else if let Some(question) = message.questions().last() {
        question.name.offset() + question.name.wire_len() + 4
    } else {
        12
    }
}

fn canonical(digest: &mut Digest, name: NameRef<'_>) {
    // RFC 8945 §4.3.3: names in TSIG variables use canonical wire form.
    for label in name.labels() {
        digest.update(&[label.len() as u8]);
        let mut lower = [0; 63];
        for (out, byte) in lower.iter_mut().zip(label) {
            *out = byte.to_ascii_lowercase();
        }
        digest.update(&lower[..label.len()]);
    }
    digest.update(&[0]);
}

fn variables(
    digest: &mut Digest,
    owner: NameRef<'_>,
    algorithm: NameRef<'_>,
    time: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) {
    canonical(digest, owner);
    digest.update(&[0, 255, 0, 0, 0, 0]);
    canonical(digest, algorithm);
    digest.update(&time.to_be_bytes()[2..]);
    digest.update(&fudge.to_be_bytes());
    digest.update(&error.to_be_bytes());
    digest.update(&(other.len() as u16).to_be_bytes());
    digest.update(other);
}
