pub(crate) fn setup(cursor: &mut pharos_corefile::Cursor<'_>, block: &mut pharos_corefile::BlockContext<crate::Chain>) -> Result<(), pharos_corefile::Error> {
    use crate::acl;

    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    block.config.acl = Some(acl::Acl::parse(cursor, &domains)?);
    Ok(())
}
