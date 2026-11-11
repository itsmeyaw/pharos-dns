pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::timeouts;

    block.config.timeouts = Some(timeouts::parse(cursor)?);
    Ok(())
}
