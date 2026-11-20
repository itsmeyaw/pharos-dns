pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::grpc_server;

    // CoreDNS v1.15.0 plugin/grpc_server/setup.go: the limits live on the block, so a second `grpc_server` line cannot redefine them.
    let current = block.config.grpc_server.take().unwrap_or_default();
    block.config.grpc_server = Some(grpc_server::parse(cursor, current)?);
    Ok(())
}
