use pharos_corefile::{BlockContext, Cursor, Error};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    _block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}
