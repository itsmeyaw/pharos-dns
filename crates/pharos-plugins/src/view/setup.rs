use pharos_corefile::{BlockContext, Cursor, Error};

use crate::{Chain, expression::Expression};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    _block: &mut BlockContext<Chain>,
) -> Result<(), Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() != 1 {
        return Err(cursor.arg_err());
    }
    let mut expressions = Vec::new();
    while cursor.next_block() {
        if cursor.val() != "expr" {
            return Err(cursor.error("unknown view property"));
        }
        let source = cursor.remaining_args().join(" ");
        expressions.push(Expression::compile(&source).map_err(|err| cursor.error(err))?);
    }
    Err(cursor.error("view routing is not implemented"))
}
