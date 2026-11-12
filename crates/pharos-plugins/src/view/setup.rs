use pharos_corefile::{BlockContext, Cursor, Error};

use super::View;
use crate::{Chain, expression::Expression};

pub(crate) fn setup(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
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
    block.view = true;
    block.config.view = Some(View {
        name: args[0].clone(),
        expressions,
    });
    Ok(())
}
