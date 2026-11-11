pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() > 1 || cursor.next() {
        return Err(cursor.arg_err());
    }
    let count = args
        .first()
        .map(|arg| {
            arg.parse::<usize>()
                .ok()
                .filter(|count| (1..=1024).contains(count))
                .ok_or_else(|| cursor.error("invalid socket count"))
        })
        .transpose()?;
    block.config.multisocket = Some(count);
    Ok(())
}
