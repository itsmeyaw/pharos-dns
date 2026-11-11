pub(crate) fn setup(cursor: &mut pharos_corefile::Cursor<'_>, block: &mut pharos_corefile::BlockContext<crate::Chain>) -> Result<(), pharos_corefile::Error> {
    use crate::hosts;
    use crate::root_path;

    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let hosts = hosts::Hosts::parse_with_root(cursor, &domains, root_path(&block.config))?;
    hosts.register_hooks(&mut block.config.lifecycle);
    block.config.hosts = Some(hosts);
    Ok(())
}
