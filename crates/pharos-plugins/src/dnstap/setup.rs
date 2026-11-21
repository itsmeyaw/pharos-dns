pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    let _ = cursor;
    block.config.dnstap = Some(super::Dnstap);
    Ok(())
}
