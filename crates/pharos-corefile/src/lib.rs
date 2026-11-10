#![forbid(unsafe_code)]

mod lexer;
mod parser;

pub use lexer::{Token, lex};
pub use parser::{Error, ServerBlock, parse, parse_with_env};
