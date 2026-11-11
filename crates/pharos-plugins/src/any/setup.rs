pub(crate) fn setup(cursor: &mut pharos_corefile::Cursor<'_>, block: &mut pharos_corefile::BlockContext<crate::Chain>) -> Result<(), pharos_corefile::Error> {
    use crate::any;

    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    block.config.any = Some(any::Any);
    Ok(())
}
