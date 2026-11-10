#![forbid(unsafe_code)]

mod key;
mod lexer;
mod parser;

pub use key::{ServerBlockKey, normalize_key};
pub use lexer::{Token, lex};
pub use parser::{Error, ServerBlock, parse, parse_with_env};
