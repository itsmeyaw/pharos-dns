#![forbid(unsafe_code)]

mod name;

pub use name::{Name, NameError, NameRef, NameWirePart, NameWireParts, Origin};

mod message;
pub use message::{Message, MessageError, MessageMut, Question, Questions, Record, Records};

mod codes;
pub use codes::{Class, Opcode, Rcode, Type};

mod builder;
pub use builder::{BuildError, FixedBuffer, MessageBuffer, MessageBuilder, RdataWriter, Section};

mod edns_options;
pub use edns_options::{ClientSubnet, EdnsOption, EdnsOptionError, EdnsOptionIter, EdnsOptions};

mod edns;
pub use edns::{Opt, ResponseOpt, normalized_udp_size};

mod rdata;
pub use rdata::{Rdata, RdataError, SvcParams};

mod response;
pub use response::{ResponseClass, ResponseType, classify_response, typify_response};

mod tsig;
pub use tsig::{TsigAlgorithm, TsigError, TsigKey, TsigRecord, TsigStream};

mod tsig_key;
pub use tsig_key::{TsigKeyError, decode_secret, encode_secret, parse_key_file};
