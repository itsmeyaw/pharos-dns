//! The `GET /v1/service/<name>` reply, decoded the way Go's `encoding/json` decodes it.

use std::{fmt, net::IpAddr};

use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, MapAccess, Visitor},
};

/// The two fields of a Nomad API `ServiceRegistration` the Plugin uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Registration {
    /// Go net.ParseIP of `Address`; `None` when it is absent, empty or not an IP address.
    pub(super) address: Option<IpAddr>,
    /// Go `uint16(s.Port)`: the `Port` integer truncated to 16 bits.
    pub(super) port: u16,
}

/// Decode the reply body: a JSON array, or `null` for none.
pub(super) fn decode(body: &[u8]) -> Result<Vec<Registration>, serde_json::Error> {
    // Go encoding/json Decoder.Decode: the first JSON value is read and what follows it is ignored.
    let mut decoder = serde_json::Deserializer::from_slice(body);
    // Go encoding/json: `null` decodes into a nil slice, which has no registrations.
    Ok(Option::<Vec<Registration>>::deserialize(&mut decoder)?.unwrap_or_default())
}

impl<'de> Deserialize<'de> for Registration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RegistrationVisitor)
    }
}

struct RegistrationVisitor;

impl<'de> Visitor<'de> for RegistrationVisitor {
    type Value = Registration;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a service registration object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Registration, A::Error> {
        let mut registration = Registration {
            address: None,
            port: 0,
        };
        while let Some(field) = map.next_key::<Field>()? {
            match field {
                // Go encoding/json: a `null` value leaves the field as it was, a duplicate key overwrites it.
                Field::Address => {
                    if let Some(Address(address)) = map.next_value::<Option<Address>>()? {
                        registration.address = address;
                    }
                }
                Field::Port => {
                    if let Some(Port(port)) = map.next_value::<Option<Port>>()? {
                        registration.port = port;
                    }
                }
                Field::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(registration)
    }
}

enum Field {
    Address,
    Port,
    Other,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldVisitor;
        impl Visitor<'_> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<Field, E> {
                // Go encoding/json: object keys match struct field names case-insensitively.
                Ok(if name.eq_ignore_ascii_case("Address") {
                    Field::Address
                } else if name.eq_ignore_ascii_case("Port") {
                    Field::Port
                } else {
                    Field::Other
                })
            }
        }
        deserializer.deserialize_identifier(FieldVisitor)
    }
}

struct Address(Option<IpAddr>);

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AddressVisitor;
        impl Visitor<'_> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Address, E> {
                // Go net.ParseIP: an unparsable address stays in the Response path as an error, not a decode failure.
                Ok(Address(text.parse().ok()))
            }
        }
        deserializer.deserialize_str(AddressVisitor)
    }
}

struct Port(u16);

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortVisitor;
        impl Visitor<'_> for PortVisitor {
            type Value = Port;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an integer")
            }

            // Go encoding/json decodes into `int`, which holds 64 bits; `uint16(s.Port)` then truncates.
            fn visit_i64<E: de::Error>(self, port: i64) -> Result<Port, E> {
                Ok(Port(port as u16))
            }

            fn visit_u64<E: de::Error>(self, port: u64) -> Result<Port, E> {
                i64::try_from(port)
                    .map(|port| Port(port as u16))
                    .map_err(|_| E::custom("integer out of range"))
            }
        }
        deserializer.deserialize_i64(PortVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(address: &str, port: u16) -> Registration {
        Registration {
            address: address.parse().ok(),
            port,
        }
    }

    // Nomad API (hashicorp/nomad api v1.10.5) api/services.go ServiceRegistration, as in plugin/nomad/nomad_test.go.
    #[test]
    fn decodes_registrations() {
        let body = br#"[{"Address":"1.2.3.4","Namespace":"default","Port":23202,"ServiceName":"example"},{"Address":"1:2:3::4","Port":8000}]"#;
        assert_eq!(
            decode(body).unwrap(),
            [
                registration("1.2.3.4", 23202),
                registration("1:2:3::4", 8000)
            ]
        );
    }

    #[test]
    fn empty_and_null_bodies_have_no_registrations() {
        assert_eq!(decode(b"[]").unwrap(), []);
        assert_eq!(decode(b"null").unwrap(), []);
        assert!(decode(b"").is_err());
        assert!(decode(b"{}").is_err());
    }

    // Go encoding/json: keys match case-insensitively, unknown keys are skipped, trailing data is ignored.
    #[test]
    fn keys_match_case_insensitively_and_unknown_keys_are_skipped() {
        let body =
            br#"[{"address":"10.0.0.1","PORT":80,"Tags":["a",{"b":null}],"x":1.5}] trailing"#;
        assert_eq!(decode(body).unwrap(), [registration("10.0.0.1", 80)]);
    }

    #[test]
    fn missing_null_and_unparsable_addresses_have_no_ip() {
        let body = br#"[{"Port":1},{"Address":null,"Port":2},{"Address":"","Port":3},{"Address":"web.example","Port":4},{"Address":"fe80::1%eth0","Port":5}]"#;
        let decoded = decode(body).unwrap();
        assert_eq!(decoded.len(), 5);
        assert!(
            decoded
                .iter()
                .all(|registration| registration.address.is_none())
        );
        assert_eq!(
            decoded.iter().map(|r| r.port).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn a_null_value_keeps_an_earlier_duplicate_and_a_later_one_wins() {
        let body = br#"[{"Address":"1.1.1.1","Address":null,"Port":7,"Port":null},{"Address":"1.1.1.1","Address":"2.2.2.2"}]"#;
        assert_eq!(
            decode(body).unwrap(),
            [registration("1.1.1.1", 7), registration("2.2.2.2", 0)]
        );
    }

    // Go: `uint16(s.Port)` truncates; a JSON number that is not an integer does not decode into `int`.
    #[test]
    fn ports_truncate_to_sixteen_bits_and_must_be_integers() {
        assert_eq!(decode(br#"[{"Port":65536}]"#).unwrap()[0].port, 0);
        assert_eq!(decode(br#"[{"Port":-1}]"#).unwrap()[0].port, 65535);
        assert!(decode(br#"[{"Port":80.5}]"#).is_err());
        assert!(decode(br#"[{"Port":1e3}]"#).is_err());
        assert!(decode(br#"[{"Port":"80"}]"#).is_err());
        assert!(decode(br#"[{"Port":18446744073709551615}]"#).is_err());
    }

    #[test]
    fn wrong_types_fail_the_whole_decode() {
        assert!(decode(br#"[{"Address":4}]"#).is_err());
        assert!(decode(br#"[null]"#).is_err());
        assert!(decode(br#"["x"]"#).is_err());
        assert!(decode(br#"[{"Address":"1.2.3.4""#).is_err());
    }

    // Go net.ParseIP and `To4`: only the IPv4-mapped form counts as IPv4 later; leading zeros are rejected.
    #[test]
    fn address_text_follows_go_parse_ip() {
        let body = br#"[{"Address":"::ffff:1.2.3.4"},{"Address":"01.2.3.4"},{"Address":"1.2.3"}]"#;
        let decoded = decode(body).unwrap();
        assert_eq!(decoded[0].address, "::ffff:1.2.3.4".parse().ok());
        assert_eq!(decoded[1].address, None);
        assert_eq!(decoded[2].address, None);
    }
}
