//! MaxMind DB record schemas and their Metadata labels.

use std::fmt::{self, Write as _};

use pharos_server::Metadata;
use serde::{
    Deserialize, Deserializer,
    de::{SeqAccess, Visitor},
};

/// Fixed-capacity text; a write that does not fit fails instead of allocating.
#[derive(Clone, Copy)]
struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Text<N> {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len + value.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Publish one label; a value that does not fit the Query's Metadata buffer is omitted.
fn put(metadata: &mut Metadata<'_>, label: &'static str, value: Option<&str>) {
    metadata.insert_copied(label, value.unwrap_or_default());
}

fn put_display(metadata: &mut Metadata<'_>, label: &'static str, value: Option<impl fmt::Display>) {
    let mut text = Text::<40>::default();
    if let Some(value) = value
        && write!(text, "{value}").is_err()
    {
        return;
    }
    put(metadata, label, Some(text.as_str()));
}

/// An MMDB unsigned integer of any width; databases differ (the CoreDNS fixtures use uint64).
// CoreDNS v1.15.0 geoip2-golang v2.4.0 ASN: the number is a Go `uint` decoded from any integer type.
#[derive(Clone, Copy, Default)]
struct Unsigned(u64);

impl<'de> Deserialize<'de> for Unsigned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Integer;
        impl Visitor<'_> for Integer {
            type Value = Unsigned;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned integer")
            }

            fn visit_u16<E: serde::de::Error>(self, value: u16) -> Result<Unsigned, E> {
                Ok(Unsigned(value.into()))
            }

            fn visit_u32<E: serde::de::Error>(self, value: u32) -> Result<Unsigned, E> {
                Ok(Unsigned(value.into()))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Unsigned, E> {
                Ok(Unsigned(value))
            }

            fn visit_i32<E: serde::de::Error>(self, value: i32) -> Result<Unsigned, E> {
                u64::try_from(value)
                    .map(Unsigned)
                    .map_err(|_| E::custom("negative integer"))
            }
        }
        deserializer.deserialize_any(Integer)
    }
}

impl fmt::Display for Unsigned {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// An MMDB float or double.
// CoreDNS v1.15.0 maxminddb-golang v2.6.0: a float32 coordinate widens to float64.
#[derive(Clone, Copy, Default)]
struct Coordinate(f64);

impl<'de> Deserialize<'de> for Coordinate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Float;
        impl Visitor<'_> for Float {
            type Value = Coordinate;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a float")
            }

            fn visit_f32<E: serde::de::Error>(self, value: f32) -> Result<Coordinate, E> {
                Ok(Coordinate(value.into()))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Coordinate, E> {
                Ok(Coordinate(value))
            }
        }
        deserializer.deserialize_any(Float)
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

#[derive(Default, Deserialize)]
struct Names<'a> {
    #[serde(rename = "en", default)]
    english: Option<&'a str>,
}

#[derive(Default, Deserialize)]
struct Named<'a> {
    #[serde(borrow, default)]
    names: Names<'a>,
}

#[derive(Default, Deserialize)]
struct Continent<'a> {
    #[serde(default)]
    code: Option<&'a str>,
    #[serde(borrow, default)]
    names: Names<'a>,
}

#[derive(Default, Deserialize)]
struct Country<'a> {
    #[serde(default)]
    iso_code: Option<&'a str>,
    #[serde(default)]
    is_in_european_union: bool,
    #[serde(borrow, default)]
    names: Names<'a>,
}

#[derive(Default, Deserialize)]
struct Location<'a> {
    #[serde(default)]
    latitude: Option<Coordinate>,
    #[serde(default)]
    longitude: Option<Coordinate>,
    #[serde(default)]
    time_zone: Option<&'a str>,
}

#[derive(Default, Deserialize)]
struct Postal<'a> {
    #[serde(default)]
    code: Option<&'a str>,
}

#[derive(Deserialize)]
struct Subdivision<'a> {
    #[serde(default)]
    iso_code: Option<&'a str>,
}

/// Subdivision ISO codes joined with commas.
#[derive(Default)]
struct SubdivisionCodes {
    text: Text<128>,
    overflowed: bool,
}

impl<'de> Deserialize<'de> for SubdivisionCodes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Codes;
        impl<'de> Visitor<'de> for Codes {
            type Value = SubdivisionCodes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an array of subdivisions")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut codes = SubdivisionCodes::default();
                let mut first = true;
                while let Some(subdivision) = seq.next_element::<Subdivision<'de>>()? {
                    // CoreDNS v1.15.0 plugin/geoip/city.go setCityMetadata: codes are joined with ",", keeping empty ones.
                    let separator = if first { "" } else { "," };
                    let code = subdivision.iso_code.unwrap_or_default();
                    codes.overflowed |= write!(codes.text, "{separator}{code}").is_err();
                    first = false;
                }
                Ok(codes)
            }
        }
        deserializer.deserialize_seq(Codes)
    }
}

/// Fields of the City, Country and Enterprise schemas that become labels.
#[derive(Default, Deserialize)]
pub(super) struct City<'a> {
    #[serde(borrow, default)]
    city: Named<'a>,
    #[serde(borrow, default)]
    continent: Continent<'a>,
    #[serde(borrow, default)]
    country: Country<'a>,
    #[serde(borrow, default)]
    location: Location<'a>,
    #[serde(borrow, default)]
    postal: Postal<'a>,
    #[serde(default)]
    subdivisions: SubdivisionCodes,
}

impl City<'_> {
    // CoreDNS v1.15.0 plugin/geoip/city.go setCityMetadata: a missing field is an empty label.
    pub(super) fn publish(&self, metadata: &mut Metadata<'_>) {
        put(metadata, "geoip/city/name", self.city.names.english);
        put(metadata, "geoip/country/name", self.country.names.english);
        put(
            metadata,
            "geoip/continent/name",
            self.continent.names.english,
        );
        put(metadata, "geoip/country/code", self.country.iso_code);
        if !self.subdivisions.overflowed {
            put(
                metadata,
                "geoip/subdivisions/code",
                Some(self.subdivisions.text.as_str()),
            );
        }
        put_display(
            metadata,
            "geoip/country/is_in_european_union",
            Some(self.country.is_in_european_union),
        );
        put(metadata, "geoip/continent/code", self.continent.code);
        // CoreDNS v1.15.0 plugin/geoip/city.go: coordinates use base 10 at full precision, empty when absent.
        put_display(metadata, "geoip/latitude", self.location.latitude);
        put_display(metadata, "geoip/longitude", self.location.longitude);
        put(metadata, "geoip/timezone", self.location.time_zone);
        put(metadata, "geoip/postalcode", self.postal.code);
    }
}

/// Fields of the ASN schema that become labels.
#[derive(Default, Deserialize)]
pub(super) struct Asn<'a> {
    #[serde(default)]
    autonomous_system_number: Unsigned,
    #[serde(default)]
    autonomous_system_organization: Option<&'a str>,
}

impl Asn<'_> {
    // CoreDNS v1.15.0 plugin/geoip/asn.go setASNMetadata.
    pub(super) fn publish(&self, metadata: &mut Metadata<'_>) {
        put_display(
            metadata,
            "geoip/asn/number",
            Some(self.autonomous_system_number),
        );
        put(
            metadata,
            "geoip/asn/org",
            self.autonomous_system_organization,
        );
    }
}
