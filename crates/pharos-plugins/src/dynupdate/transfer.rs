use super::DynUpdate;
use crate::transfer::{Transfer, TransferRequest, Transferer};
use pharos_proto::NameRef;
use pharos_server::{Error, Stream};

impl Transferer for DynUpdate {
    fn bind_transfer(&self, transfer: Option<&Transfer>) {
        self.notifier.bind(transfer);
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        // RFC 5936 §2.1.2: Serve transfers only for the configured zone name.
        if !NameRef::parse(self.config.origin.as_wire(), 0).is_ok_and(|name| name == request.zone) {
            return Ok(None);
        }
        let shared = self.snapshot().map_err(|_| Error::InvalidQuery)?;
        Ok(Some(shared.current.load_full().transfer(request)?))
    }
}
