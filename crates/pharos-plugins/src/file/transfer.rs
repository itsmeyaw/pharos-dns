use super::*;
use crate::transfer::{Transfer, TransferRequest, Transferer};
use pharos_proto::NameRef;
use pharos_server::{Error, Stream};

impl Transferer for File {
    fn bind_transfer(&self, transfer: Option<&Transfer>) {
        self.notifier.bind(transfer);
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        // RFC 1995 §3: IXFR QNAME identifies the requested zone.
        let Some(loaded) = self.zones.iter().find(|zone| {
            NameRef::parse(zone.apex.as_wire(), 0).is_ok_and(|name| name == request.zone)
        }) else {
            return Ok(None);
        };
        let zone = loaded.current.load_full().ok_or(Error::InvalidQuery)?;
        Ok(Some(zone.transfer(request)?))
    }
}
