use std::fmt;

macro_rules! dns_code {
    ($(#[$doc:meta])* $name:ident, $raw:ty, $prefix:literal, { $($constant:ident = $value:literal => $text:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub $raw);

        impl $name {
            $(pub const $constant: Self = Self($value);)*
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($value => f.write_str($text),)*
                    value => write!(f, "{}{value}", $prefix),
                }
            }
        }
    };
}

dns_code! {
    /// A DNS Message operation code. Unknown values display as a decimal number.
    Opcode, u8, "", {
        QUERY = 0 => "QUERY",
        IQUERY = 1 => "IQUERY",
        STATUS = 2 => "STATUS",
        NOTIFY = 4 => "NOTIFY",
        UPDATE = 5 => "UPDATE",
    }
}

impl Opcode {
    /// DNS Stateful Operations (not named by miekg/dns's presentation map).
    pub const STATEFUL: Self = Self(6);
}

dns_code! {
    /// A DNS Response code, including extended RCODEs. Unknown values display as a decimal number.
    Rcode, u16, "", {
        NOERROR = 0 => "NOERROR",
        FORMERR = 1 => "FORMERR",
        SERVFAIL = 2 => "SERVFAIL",
        NXDOMAIN = 3 => "NXDOMAIN",
        NOTIMP = 4 => "NOTIMP",
        REFUSED = 5 => "REFUSED",
        YXDOMAIN = 6 => "YXDOMAIN",
        YXRRSET = 7 => "YXRRSET",
        NXRRSET = 8 => "NXRRSET",
        NOTAUTH = 9 => "NOTAUTH",
        NOTZONE = 10 => "NOTZONE",
        DSOTYPENI = 11 => "DSOTYPENI",
        BADSIG = 16 => "BADSIG",
        BADKEY = 17 => "BADKEY",
        BADTIME = 18 => "BADTIME",
        BADMODE = 19 => "BADMODE",
        BADNAME = 20 => "BADNAME",
        BADALG = 21 => "BADALG",
        BADTRUNC = 22 => "BADTRUNC",
        BADCOOKIE = 23 => "BADCOOKIE",
    }
}

impl Rcode {
    /// The EDNS bad-version code shares its value with TSIG's BADSIG.
    pub const BADVERS: Self = Self::BADSIG;

    /// Combines the header's low four RCODE bits with the OPT extended byte.
    #[must_use]
    pub const fn from_parts(header: u8, extended: u8) -> Self {
        // RFC 6891 §6.1.3: the extended RCODE adds eight high bits to the header's four.
        Self(((extended as u16) << 4) | ((header & 0x0f) as u16))
    }
}

dns_code! {
    /// A DNS class or QCLASS. Unknown values display in RFC 3597 `CLASS` form.
    Class, u16, "CLASS", {
        IN = 1 => "IN",
        CS = 2 => "CS",
        CH = 3 => "CH",
        HS = 4 => "HS",
        NONE = 254 => "NONE",
        ANY = 255 => "CLASS255",
    }
}

dns_code! {
    /// A DNS resource record type or QTYPE. Unknown values display in RFC 3597 `TYPE` form.
    Type, u16, "TYPE", {
        NONE = 0 => "None",
        A = 1 => "A",
        NS = 2 => "NS",
        MD = 3 => "MD",
        MF = 4 => "MF",
        CNAME = 5 => "CNAME",
        SOA = 6 => "SOA",
        MB = 7 => "MB",
        MG = 8 => "MG",
        MR = 9 => "MR",
        NULL = 10 => "NULL",
        PTR = 12 => "PTR",
        HINFO = 13 => "HINFO",
        MINFO = 14 => "MINFO",
        MX = 15 => "MX",
        TXT = 16 => "TXT",
        RP = 17 => "RP",
        AFSDB = 18 => "AFSDB",
        X25 = 19 => "X25",
        ISDN = 20 => "ISDN",
        RT = 21 => "RT",
        NSAP_PTR = 23 => "NSAP-PTR",
        SIG = 24 => "SIG",
        KEY = 25 => "KEY",
        PX = 26 => "PX",
        GPOS = 27 => "GPOS",
        AAAA = 28 => "AAAA",
        LOC = 29 => "LOC",
        NXT = 30 => "NXT",
        EID = 31 => "EID",
        NIMLOC = 32 => "NIMLOC",
        SRV = 33 => "SRV",
        ATMA = 34 => "ATMA",
        NAPTR = 35 => "NAPTR",
        KX = 36 => "KX",
        CERT = 37 => "CERT",
        DNAME = 39 => "DNAME",
        OPT = 41 => "OPT",
        APL = 42 => "APL",
        DS = 43 => "DS",
        SSHFP = 44 => "SSHFP",
        IPSECKEY = 45 => "IPSECKEY",
        RRSIG = 46 => "RRSIG",
        NSEC = 47 => "NSEC",
        DNSKEY = 48 => "DNSKEY",
        DHCID = 49 => "DHCID",
        NSEC3 = 50 => "NSEC3",
        NSEC3PARAM = 51 => "NSEC3PARAM",
        TLSA = 52 => "TLSA",
        SMIMEA = 53 => "SMIMEA",
        HIP = 55 => "HIP",
        NINFO = 56 => "NINFO",
        RKEY = 57 => "RKEY",
        TALINK = 58 => "TALINK",
        CDS = 59 => "CDS",
        CDNSKEY = 60 => "CDNSKEY",
        OPENPGPKEY = 61 => "OPENPGPKEY",
        CSYNC = 62 => "CSYNC",
        ZONEMD = 63 => "ZONEMD",
        SVCB = 64 => "SVCB",
        HTTPS = 65 => "HTTPS",
        SPF = 99 => "SPF",
        UINFO = 100 => "UINFO",
        UID = 101 => "UID",
        GID = 102 => "GID",
        UNSPEC = 103 => "UNSPEC",
        NID = 104 => "NID",
        L32 = 105 => "L32",
        L64 = 106 => "L64",
        LP = 107 => "LP",
        EUI48 = 108 => "EUI48",
        EUI64 = 109 => "EUI64",
        NXNAME = 128 => "NXNAME",
        TKEY = 249 => "TKEY",
        TSIG = 250 => "TSIG",
        IXFR = 251 => "IXFR",
        AXFR = 252 => "AXFR",
        MAILB = 253 => "MAILB",
        MAILA = 254 => "MAILA",
        ANY = 255 => "ANY",
        URI = 256 => "URI",
        CAA = 257 => "CAA",
        AVC = 258 => "AVC",
        AMTRELAY = 260 => "AMTRELAY",
        RESINFO = 261 => "RESINFO",
        TA = 32768 => "TA",
        DLV = 32769 => "DLV",
        RESERVED = 65535 => "Reserved",
    }
}
