#![forbid(unsafe_code)]

mod cursor;
mod helpers;
mod key;
mod lexer;
mod parser;

pub use cursor::Cursor;
pub use helpers::{Fallthrough, normalize_domain, origins_from_args_or_server_block};
pub use key::{ServerBlockKey, normalize_key};
pub use lexer::{Token, lex};
pub use parser::{Error, ServerBlock, parse, parse_with_env};
