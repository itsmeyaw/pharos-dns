pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::https;

    // CoreDNS v1.15.0 plugin/https/setup.go: the limits live on the block, so a second `https` line cannot redefine them.
    let current = block.config.https.take().unwrap_or_default();
    block.config.https = Some(https::parse(cursor, current)?);
    Ok(())
}
