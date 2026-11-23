//! geoip Directive: MaxMind DB lookups published as Metadata.

pub(crate) mod setup;

mod record;

use std::{fs, net::IpAddr};

use maxminddb::Reader;
use pharos_corefile::{Cursor, Error};
use pharos_proto::EdnsOption;
use pharos_server::{Context, Metadata, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
    city: bool,
    asn: bool,
    edns_subnet: bool,
}

/// Which schemas a database type provides, as `(city, asn)`.
// CoreDNS v1.15.0 geoip2-golang v2.4.0 reader.go getDBType: the type string selects the lookup methods.
fn schemas(database_type: &str) -> Option<(bool, bool)> {
    match database_type {
        "GeoIP-Anonymous-Plus"
        | "GeoIP2-Anonymous-IP"
        | "GeoIP2-Connection-Type"
        | "GeoIP2-Domain" => Some((false, false)),
        "DBIP-ASN-Lite (compat=GeoLite2-ASN)"
        | "GeoLite2-ASN"
        | "GeoIP2-ISP"
        | "GeoIP2-Precision-ISP" => Some((false, true)),
        "DBIP-City-Lite"
        | "DBIP-Country-Lite"
        | "DBIP-Country"
        | "DBIP-Location (compat=City)"
        | "GeoLite2-City"
        | "GeoIP-City-Redacted-US"
        | "GeoIP2-City"
        | "GeoIP2-City-Africa"
        | "GeoIP2-City-Asia-Pacific"
        | "GeoIP2-City-Europe"
        | "GeoIP2-City-North-America"
        | "GeoIP2-City-South-America"
        | "GeoIP2-Precision-City"
        | "GeoLite2-Country"
        | "GeoIP2-Country"
        | "DBIP-ISP (compat=Enterprise)"
        | "DBIP-Location-ISP (compat=Enterprise)"
        | "GeoIP-Enterprise-Redacted-US"
        | "GeoIP2-Enterprise" => Some((true, false)),
        _ => None,
    }
}

impl GeoIp {
    pub(crate) fn open(path: &str, edns_subnet: bool) -> Result<Self, String> {
        // CoreDNS v1.15.0 plugin/geoip/geoip.go newGeoIP: open failures are reported with the path.
        let bytes = fs::read(path)
            .map_err(|error| format!("failed to open database file: open {path}: {error}"))?;
        let reader = Reader::from_source(bytes)
            .map_err(|error| format!("failed to open database file: {error}"))?;
        let database_type = &reader.metadata().database_type;
        let (city, asn) = schemas(database_type).ok_or_else(|| {
            format!(
                "failed to open database file: geoip2: reader does not support the {database_type:?} database type"
            )
        })?;
        // CoreDNS v1.15.0 plugin/geoip/geoip.go newGeoIP: a database without a supported schema is rejected.
        if !city && !asn {
            return Err("database does not provide any supported schema (city, asn)".to_owned());
        }
        Ok(Self {
            reader,
            city,
            asn,
            edns_subnet,
        })
    }

    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let mut path = None;
        let mut edns_subnet = false;
        // CoreDNS v1.15.0 plugin/geoip/setup.go geoipParse.
        while cursor.next() {
            if !cursor.next_arg() {
                return Err(cursor.arg_err());
            }
            if path.is_some() {
                return Err(cursor.error("configuring multiple databases is not supported"));
            }
            path = Some(cursor.val().to_owned());
            if !cursor.remaining_args().is_empty() {
                return Err(cursor.arg_err());
            }
            while cursor.next_block() {
                if cursor.val() != "edns-subnet" {
                    return Err(cursor.error(format!("unknown property {:?}", cursor.val())));
                }
                edns_subnet = true;
            }
        }
        let path = path.ok_or_else(|| cursor.arg_err())?;
        Self::open(&path, edns_subnet).map_err(|message| cursor.error(message))
    }

    /// The address to look up for a Query.
    fn lookup_address(&self, cx: &Context<'_, '_>) -> IpAddr {
        if self.edns_subnet
            && let Some(opt) = cx.query.opt()
        {
            // RFC 7871 §6: the first Client Subnet option names the address; CoreDNS stops at it.
            for option in opt.options().iter() {
                if let EdnsOption::ClientSubnet(subnet) = option {
                    return subnet.address();
                }
            }
        }
        // CoreDNS v1.15.0 request/request.go IP: Go prints an IPv4-mapped IPv6 source as plain IPv4.
        cx.client.ip().to_canonical()
    }

    /// Publish the labels of every schema the database provides for `address`.
    fn publish(&self, address: IpAddr, metadata: &mut Metadata<'_>) {
        // CoreDNS v1.15.0 maxminddb-golang v2.6.0 lookupPointer: IPv6 in an IPv4-only database is an error and publishes nothing.
        if address.is_ipv6() && self.reader.metadata().ip_version == 4 {
            return;
        }
        let Ok(result) = self.reader.lookup(address) else {
            return;
        };
        // CoreDNS v1.15.0 plugin/geoip/geoip.go Metadata: an address absent from the database yields zero-valued labels.
        if self.city
            && let Ok(record) = result.decode::<record::City<'_>>()
        {
            record.unwrap_or_default().publish(metadata);
        }
        if self.asn
            && let Ok(record) = result.decode::<record::Asn<'_>>()
        {
            record.unwrap_or_default().publish(metadata);
        }
    }

    pub(crate) fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        let address = self.lookup_address(cx);
        self.publish(address, &mut cx.metadata);
    }
}

impl Plugin for GeoIp {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // CoreDNS v1.15.0 plugin/geoip/geoip.go ServeDNS: the Plugin only publishes Metadata and calls Next.
        next.run(cx).await
    }
}

#[cfg(test)]
mod tests;
