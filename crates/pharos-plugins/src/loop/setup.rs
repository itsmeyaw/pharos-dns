pub(crate) fn setup(cursor: &mut pharos_corefile::Cursor<'_>, block: &mut pharos_corefile::BlockContext<crate::Chain>) -> Result<(), pharos_corefile::Error> {
    use crate::r#loop;

    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    let domain = block.keys().first().map_or(".", |key| key.domain.as_str());
    block.config.r#loop = Some(r#loop::Loop::new(domain));
    Ok(())
}
