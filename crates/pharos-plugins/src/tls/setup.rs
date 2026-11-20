pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::tls;

    // CoreDNS v1.15.0 plugin/tls/tls.go parseTLS: the Directive stores one TLS configuration on the Server Block; a relative path joins `root`.
    let root = crate::root_path(&block.config);
    block.config.tls = Some(tls::parse(cursor, root)?);
    Ok(())
}
