pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    block.config.proxyproto = Some(crate::proxyproto::parse(cursor)?);
    Ok(())
}
