pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::trace;

    // CoreDNS v1.15.0 plugin/trace/setup.go traceParse: the service endpoint is the first listen host with the block's port.
    // shortcut: a block with keys on several ports reports the first key's port, split the block's ports when a collector needs each.
    let port = block.keys().first().map_or("", |key| key.port.as_str());
    let config = trace::parse(cursor, &block.listen_addresses, port)?;
    let trace = trace::Trace::new(config);
    trace.register_hooks(&mut block.config.lifecycle);
    block.config.trace = Some(trace);
    Ok(())
}
