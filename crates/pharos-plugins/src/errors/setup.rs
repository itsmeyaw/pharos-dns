pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::errors;

    let plugin = errors::parse(cursor)?;
    plugin.register_shutdown(&mut block.config.lifecycle);
    block.config.errors = Some(plugin);
    Ok(())
}
