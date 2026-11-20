pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::https3;

    // CoreDNS v1.15.0 plugin/https3/setup.go parseDOH3: the limits live on the Server Block's config.
    block.config.https3 = Some(https3::parse(cursor)?);
    Ok(())
}
