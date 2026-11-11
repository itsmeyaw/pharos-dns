pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::nsid;

    block.config.nsid = Some(nsid::Nsid::parse(cursor)?);
    Ok(())
}
