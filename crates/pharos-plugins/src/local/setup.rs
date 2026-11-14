pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::local;

    // RFC 6303 §3: Enable local zones only when the local block is configured.
    block.config.local = Some(local::Local::parse(cursor)?);
    Ok(())
}
