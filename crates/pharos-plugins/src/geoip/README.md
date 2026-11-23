# geoip

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/geoip/README.md)

## geoip

- The database is read with the `maxminddb` crate (ISC) and loaded fully into memory at startup; CoreDNS memory-maps it. The file is not reloaded when it changes, as in CoreDNS.
- The supported database types are those of `oschwald/geoip2-golang/v2` v2.4.0 (`getDBType`). A type with no City or ASN schema (for example `GeoIP2-Domain`) fails setup with `database does not provide any supported schema (city, asn)`; an unknown type fails with `reader does not support the "<type>" database type`.
- An address absent from the database publishes the schema's labels with zero values (empty strings, `geoip/country/is_in_european_union` `false`, `geoip/asn/number` `0`), as CoreDNS v1.15.0 does. An IPv6 address looked up in an IPv4-only database publishes no labels.
- `edns-subnet` uses the address of the first EDNS Client Subnet option (RFC 7871 §6) and falls back to the source address when there is none. An IPv4-mapped IPv6 source address is looked up as IPv4, as Go prints it.
- Labels are copied into the Query's fixed Metadata buffer, which holds 16 labels and 1,280 bytes shared with the Kubernetes labels (see the [metadata notes](../metadata/README.md)). A label whose value does not fit is omitted instead of published truncated; `geoip/subdivisions/code` is also omitted when the joined codes exceed 128 bytes. CoreDNS has no such limits.
- A lookup or record decoding failure publishes no labels and is not logged; CoreDNS logs it at debug level.
- Numeric labels (`geoip/latitude`, `geoip/longitude`, `geoip/asn/number`) use base 10 like CoreDNS; non-finite coordinates are not formatted like Go's `+Inf`.
- The Plugin copies no strings and allocates nothing per Query in Pharos code; the allocation test pins that.

## Sources

- Derived from CoreDNS v1.15.0 plugin/geoip/geoip_test.go TestMetadata and TestMetadataUnknownIP.
- Derived from CoreDNS v1.15.0 plugin/geoip/setup_test.go TestGeoIPParse.
- The `.mmdb` fixtures in `tests/fixtures/geoip` are copied from CoreDNS v1.15.0 `plugin/geoip/testdata`.

- [CoreDNS v1.15.0 `plugin/geoip`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/geoip)
