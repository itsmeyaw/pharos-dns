pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    // coredns/caddy v1.1.4 onevent/on.go `setup`: parse the hooks, then register each as an event hook.
    for hook in crate::on::parse(cursor)? {
        hook.register(&mut block.config.lifecycle);
    }
    Ok(())
}
