pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::loadbalance;
    use crate::root_path;

    let plugin = loadbalance::LoadBalance::parse(cursor, root_path(&block.config))?;
    plugin.register_hooks(&mut block.config.lifecycle);
    block.config.loadbalance = Some(plugin);
    Ok(())
}
