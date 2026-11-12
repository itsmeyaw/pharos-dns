use pharos_proto::{Message, NameRef, Rdata};

pub(crate) fn name_len(name: NameRef<'_>) -> usize {
    1 + name.labels().map(|label| label.len() + 1).sum::<usize>()
}

pub(crate) fn message_len(message: Message<'_>) -> usize {
    let questions = message
        .questions()
        .map(|q| name_len(q.name) + 4)
        .sum::<usize>();
    let records = message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .map(|record| {
            let mut size = Some(record.rdata.len());
            let mut expand = |name: NameRef<'_>| {
                // RFC 1035 §4.1.4: a compressed name may be shorter than its expanded form.
                size = size
                    .and_then(|size| size.checked_sub(name.wire_len()))
                    .and_then(|size| size.checked_add(name_len(name)));
            };
            match record.data() {
                Ok(Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name)) => expand(name),
                Ok(Rdata::Mx { exchange, .. }) => expand(exchange),
                Ok(Rdata::Soa { mname, rname, .. }) => {
                    expand(mname);
                    expand(rname);
                }
                Ok(
                    Rdata::Srv { target, .. }
                    | Rdata::Svcb { target, .. }
                    | Rdata::Https { target, .. },
                ) => expand(target),
                Ok(Rdata::Naptr { replacement, .. }) => expand(replacement),
                Ok(Rdata::Rrsig { signer, .. }) => expand(signer),
                Ok(Rdata::Nsec { next, .. }) => expand(next),
                Ok(Rdata::Tsig { algorithm, .. }) => expand(algorithm),
                // shortcut: unsupported or malformed name-bearing RDATA stays encoded; extend pharos-proto to decode it.
                _ => {}
            }
            name_len(record.name) + 10 + size.unwrap_or(record.rdata.len())
        })
        .sum::<usize>();
    12 + questions + records
}
