use super::*;
use crate::transfer::{Transfer, TransferRequest, Transferer};
use pharos_server::{Error, Stream};

impl Auto {
    pub(crate) fn transfer_query(
        &self,
        request: TransferRequest<'_>,
    ) -> Result<Option<Stream>, Error> {
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in request.zone.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            wire[len..len + label.len()].make_ascii_lowercase();
            len += label.len();
        }
        // RFC 4343 §3: incoming DNS names compare case-insensitively.
        let zone =
            pharos_proto::NameRef::parse(&wire[..len + 1], 0).map_err(|_| Error::InvalidQuery)?;
        self.transfer(TransferRequest { zone, ..request })
    }
}

impl Transferer for Auto {
    fn bind_transfer(&self, transfer: Option<&Transfer>) {
        self.shared.notifier.bind(transfer);
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        let zones = self.shared.zones.load();
        let mut text = NameText {
            bytes: [0; 1024],
            len: 0,
        };
        write!(&mut text, "{}", request.zone).map_err(|_| Error::InvalidQuery)?;
        let name = std::str::from_utf8(&text.bytes[..text.len]).map_err(|_| Error::InvalidQuery)?;
        let Some(entry) = zones.get(name) else {
            return Ok(None);
        };
        let zone = entry.current.load_full().ok_or(Error::InvalidQuery)?;
        Ok(Some(zone.transfer(request)?))
    }
}
