//! Root Directive configuration.

use std::{io, path::PathBuf};

use pharos_corefile::{Cursor, Error};

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<PathBuf, Error> {
    let mut root = None;
    while cursor.next() {
        if !cursor.next_arg() {
            return Err(cursor.arg_err());
        }
        root = Some(PathBuf::from(cursor.val()));
    }
    let path = root.ok_or_else(|| cursor.arg_err())?;
    match std::fs::metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => pharos_server::logging::log(
            "WARN",
            "root",
            &format!("Root path does not exist: {}", path.display()),
        ),
        Err(error) => {
            return Err(cursor.error(format!(
                "unable to access root path '{}': {error}",
                path.display()
            )));
        }
    }
    Ok(path)
}
