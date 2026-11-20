pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::quic;

    // CoreDNS v1.15.0 plugin/quic/setup.go parseQuic: the limits live on the Server Block's config.
    block.config.quic = Some(quic::parse(cursor)?);
    Ok(())
}
