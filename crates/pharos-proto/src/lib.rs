#![forbid(unsafe_code)]

mod name;

pub use name::{Name, NameError, NameRef, Origin};

mod message;
pub use message::{Message, MessageError, MessageMut, Question, Questions, Record, Records};

mod codes;
pub use codes::{Class, Opcode, Rcode, Type};

mod builder;
pub use builder::{BuildError, MessageBuilder, RdataWriter, Section};

mod edns_options;
pub use edns_options::{ClientSubnet, EdnsOption, EdnsOptionError, EdnsOptionIter, EdnsOptions};

mod edns;
pub use edns::{Opt, ResponseOpt, normalized_udp_size};

mod rdata;
pub use rdata::{Rdata, RdataError, SvcParams};

mod response;
pub use response::{ResponseClass, ResponseType, classify_response, typify_response};
