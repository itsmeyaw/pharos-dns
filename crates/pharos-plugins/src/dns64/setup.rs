pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::dns64;

    block.config.dns64 = Some(dns64::Dns64::parse(cursor)?);
    Ok(())
}
