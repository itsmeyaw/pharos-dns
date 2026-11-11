pub(crate) fn setup(cursor: &mut pharos_corefile::Cursor<'_>, block: &mut pharos_corefile::BlockContext<crate::Chain>) -> Result<(), pharos_corefile::Error> {
    use crate::shed;

    cursor.next();
    if !cursor.remaining_args().is_empty() || cursor.next_block() {
        return Err(cursor.arg_err());
    }
    if block.keys().iter().any(|key| key.transport != "dns") {
        return Err(cursor.error("shed requires plain DNS"));
    }
    block.config.shed = Some(shed::Shed);
    Ok(())
}
