use super::*;
use crate::transfer::{Transfer, TransferRequest, Transferer};
use pharos_server::{Error, Stream};

impl Transferer for Secondary {
    fn bind_transfer(&self, transfer: Option<&Transfer>) {
        self.shared.notifier.bind(transfer);
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        let zones = self.shared.zones.load();
        let Some(zone) = zones.iter().find(|zone| {
            NameRef::parse(zone.config.apex.as_wire(), 0).is_ok_and(|apex| apex == request.zone)
        }) else {
            return Ok(None);
        };
        let snapshot = zone.current.load_full().ok_or(Error::InvalidQuery)?;
        Ok(Some(snapshot.transfer(request)?))
    }
}
