pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    for hook in crate::on::parse(cursor)? {
        hook.register(&mut block.config.lifecycle);
    }
    Ok(())
}
