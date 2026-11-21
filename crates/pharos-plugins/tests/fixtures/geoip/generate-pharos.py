# Generates the Pharos-written fixtures in this directory with mmdb-writer 0.2.7 (MIT):
#   pip install mmdb-writer netaddr && python3 generate-pharos.py
# The GeoLite2-*.mmdb files are CoreDNS's; see README.md.
from mmdb_writer import MMDBWriter, MmdbU32
from netaddr import IPSet

CAMBRIDGE = {
    "city": {"names": {"en": "Cambridge"}},
    "country": {"iso_code": "GB", "names": {"en": "United Kingdom"}},
}

# IPv4-only: an IPv6 lookup is an error and publishes nothing.
v4 = MMDBWriter(ip_version=4, database_type="DBIP-City-Lite", languages=["en"])
v4.insert_network(IPSet(["81.2.69.142/32"]), CAMBRIDGE)
v4.to_db_file("Pharos-City-IPv4.mmdb")

# IPv6 with float32 coordinates, UTF-8 names, a subdivision without iso_code,
# and a record whose joined subdivision codes exceed 128 bytes.
city = MMDBWriter(ip_version=6, database_type="DBIP-City-Lite", languages=["en"], float_type="f32")
city.insert_network(IPSet(["2001:db8:1::/48"]), {
    "city": {"names": {"en": "Zürich"}},
    "continent": {"code": "EU", "names": {"en": "Europe"}},
    "country": {"iso_code": "CH", "names": {"en": "Switzerland"}},
    "location": {"latitude": 47.5, "longitude": 8.25, "time_zone": "Europe/Zurich"},
    "postal": {"code": "8001"},
    "subdivisions": [{"iso_code": "ZH"}, {"names": {"en": "No code"}}, {"iso_code": "X"}],
})
city.insert_network(IPSet(["2001:db8:3::/48"]), {
    "country": {"iso_code": "CH"},
    "subdivisions": [{"iso_code": "ABC"} for _ in range(40)],
})
city.to_db_file("Pharos-City-IPv6.mmdb")

# An ISP database provides the ASN schema; its number is uint32.
isp = MMDBWriter(ip_version=6, database_type="GeoIP2-ISP", languages=["en"])
isp.insert_network(IPSet(["2001:db8:2::/48"]), {
    "autonomous_system_number": MmdbU32(64500),
    "autonomous_system_organization": "Example ISP",
})
isp.to_db_file("Pharos-ISP-IPv6.mmdb")
