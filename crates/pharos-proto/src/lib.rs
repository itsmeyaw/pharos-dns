#![forbid(unsafe_code)]

mod name;

pub use name::{Name, NameError, NameRef, Origin};

mod message;
pub use message::{Message, MessageError, MessageMut, Question, Questions, Record, Records};
