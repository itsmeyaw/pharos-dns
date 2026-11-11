pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::bufsize;

    block.config.bufsize = Some(bufsize::Bufsize::parse(cursor)?);
    Ok(())
}
