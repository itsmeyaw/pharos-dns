pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::tls;

    let root = crate::root_path(&block.config);
    block.config.tls = Some(tls::parse(cursor, root)?);
    Ok(())
}
