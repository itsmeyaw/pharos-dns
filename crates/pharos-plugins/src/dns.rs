use pharos_proto::{BuildError, Message, MessageBuilder, Section};

// RFC 1034 §4.3.2 and RFC 2308 §3: preserve Authority records from the final CNAME cycle.
pub(crate) fn copy_authorities(
    builder: &mut MessageBuilder<'_>,
    message: &Message<'_>,
) -> Result<(), BuildError> {
    for record in message.authorities() {
        if let Ok(data) = record.data() {
            builder.record_with(
                Section::Authority,
                record.name,
                record.rtype,
                record.class,
                record.ttl,
                |w| data.write(w),
            )?;
        }
    }
    Ok(())
}
