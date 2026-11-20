pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    // CoreDNS v1.15.0 plugin/proxyproto/setup.go setup: the Directive configures PROXY protocol for the Server Block.
    block.config.proxyproto = Some(crate::proxyproto::parse(cursor)?);
    Ok(())
}
