#![forbid(unsafe_code)]

mod name;

pub use name::{Name, NameError, NameRef, Origin};

mod message;
pub use message::{Message, MessageError, MessageMut, Question, Questions, Record, Records};

mod codes;
pub use codes::{Class, Opcode, Rcode, Type};

mod builder;
pub use builder::{BuildError, MessageBuilder, RdataWriter, Section};
