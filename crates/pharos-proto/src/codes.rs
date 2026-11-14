use std::fmt;

macro_rules! dns_code {
    ($(#[$doc:meta])* $name:ident, $raw:ty, $prefix:literal, { $($constant:ident = $value:literal => $text:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub $raw);

        impl $name {
            $(pub const $constant: Self = Self($value);)*

            /// Finds a known presentation mnemonic, ignoring ASCII case.
            #[must_use]
            pub fn from_mnemonic(value: &str) -> Option<Self> {
                $(if value.eq_ignore_ascii_case($text) { return Some(Self($value)); })*
                None
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($value => f.write_str($text),)*
                    // RFC 3597 §5: Unknown types and classes use TYPE or CLASS plus decimal code.
                    value => write!(f, "{}{value}", $prefix),
                }
            }
        }
    };
}

// RFC 1035 §4.1.1: OPCODE identifies the message operation.
dns_code! {
    // RFC 6895 §2.2: DNS OpCode values use the four-bit OpCode registry.
    /// A DNS Message operation code. Unknown values display as a decimal number.
    Opcode, u8, "", {
        QUERY = 0 => "QUERY",
        IQUERY = 1 => "IQUERY",
        STATUS = 2 => "STATUS",
        NOTIFY = 4 => "NOTIFY",
        // RFC 2136 §1.3: UPDATE uses opcode value 5.
        UPDATE = 5 => "UPDATE",
    }
}

impl Opcode {
    // RFC 8490 §5.4.1: OPCODE value 6 identifies DNS Stateful Operations.
    /// DNS Stateful Operations (not named by miekg/dns's presentation map).
    pub const STATEFUL: Self = Self(6);
}

// RFC 1035 §4.1.1: RCODE identifies the response status.
dns_code! {
    // RFC 6895 §2.3: Header, OPT, TSIG, and TKEY share RCODEs, with context exceptions 9 and 16.
    /// A DNS Response code, including extended RCODEs. Unknown values display as a decimal number.
    Rcode, u16, "", {
        NOERROR = 0 => "NOERROR",
        FORMERR = 1 => "FORMERR",
        SERVFAIL = 2 => "SERVFAIL",
        NXDOMAIN = 3 => "NXDOMAIN",
        NOTIMP = 4 => "NOTIMP",
        REFUSED = 5 => "REFUSED",
        // RFC 2136 §1.3: YXDOMAIN through NOTZONE use RCODE values 6 through 10.
        YXDOMAIN = 6 => "YXDOMAIN",
        YXRRSET = 7 => "YXRRSET",
        NXRRSET = 8 => "NXRRSET",
        NOTAUTH = 9 => "NOTAUTH",
        NOTZONE = 10 => "NOTZONE",
        // RFC 8490 §5.4.1: DSOTYPENI is RCODE 11.
        DSOTYPENI = 11 => "DSOTYPENI",
        // RFC 8945 §3: DNS RCODE BADSIG is 16.
        BADSIG = 16 => "BADSIG",
        // RFC 8945 §3: DNS RCODE BADKEY is 17.
        BADKEY = 17 => "BADKEY",
        // RFC 8945 §3: DNS RCODE BADTIME is 18.
        BADTIME = 18 => "BADTIME",
        // RFC 2930 §7: TKEY errors 19, 20, and 21 mean BADMODE, BADNAME, and BADALG.
        BADMODE = 19 => "BADMODE",
        BADNAME = 20 => "BADNAME",
        BADALG = 21 => "BADALG",
        // RFC 8945 §3: DNS RCODE BADTRUNC is 22.
        BADTRUNC = 22 => "BADTRUNC",
        BADCOOKIE = 23 => "BADCOOKIE",
    }
}

impl Rcode {
    // RFC 6895 §2.3: RCODE 16 means BADVERS in OPT and BADSIG in TSIG.
    // RFC 6891 §9: EDNS Extended RCODE 16 is BADVERS.
    /// The EDNS bad-version code shares its value with TSIG's BADSIG.
    pub const BADVERS: Self = Self::BADSIG;

    /// Combines the header's low four RCODE bits with the OPT extended byte.
    #[must_use]
    pub const fn from_parts(header: u8, extended: u8) -> Self {
        // RFC 6895 §3.1.3: OPT extends the effective RCODE from four bits to twelve.
        // RFC 6891 §6.1.3: the extended RCODE adds eight high bits to the header's four.
        Self(((extended as u16) << 4) | ((header & 0x0f) as u16))
    }
}

// RFC 1035 §3.6: TYPE and CLASS use disjoint mnemonic spaces.
dns_code! {
    // RFC 1035 §4.1.3: CLASS is a 16-bit unsigned field.
    /// A DNS class or QCLASS. Unknown values display in RFC 3597 `CLASS` form.
    Class, u16, "CLASS", {
        IN = 1 => "IN",
        CS = 2 => "CS",
        CH = 3 => "CH",
        HS = 4 => "HS",
        // RFC 2136 §1.3: NONE is CLASS 254.
        NONE = 254 => "NONE",
        ANY = 255 => "CLASS255",
    }
}

// RFC 1034 §3.6: RR types identify the resource described by their RDATA.
dns_code! {
    // RFC 3597 §5: Unknown RR types display as TYPE followed by the decimal type code.
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
        // RFC 1183 §2.2: RP is DNS type 17.
        RP = 17 => "RP",
        // RFC 1183 §1: AFSDB is DNS type 18.
        AFSDB = 18 => "AFSDB",
        // RFC 1183 §3.1: X25 uses RR type code 19.
        X25 = 19 => "X25",
        // RFC 1183 §3.2: ISDN uses RR type code 20.
        ISDN = 20 => "ISDN",
        // RFC 1183 §3.3: RT uses RR type code 21.
        RT = 21 => "RT",
        NSAP_PTR = 23 => "NSAP-PTR",
        SIG = 24 => "SIG",
        KEY = 25 => "KEY",
        // RFC 2163 §4: PX is type 26 for X.400/RFC822 mapping data.
        PX = 26 => "PX",
        // RFC 1712 §4: GPOS is the mnemonic for DNS type code 27.
        GPOS = 27 => "GPOS",
        // RFC 3596 §2.1: AAAA is an Internet-class record type with value 28.
        AAAA = 28 => "AAAA",
        // RFC 1876 §1: LOC is DNS resource record type 29.
        LOC = 29 => "LOC",
        NXT = 30 => "NXT",
        EID = 31 => "EID",
        NIMLOC = 32 => "NIMLOC",
        // RFC 2782 §The format of the SRV RR; §IANA Considerations: SRV is type 33.
        SRV = 33 => "SRV",
        ATMA = 34 => "ATMA",
        // RFC 3403 §4.1: The NAPTR resource record has DNS type code 35.
        NAPTR = 35 => "NAPTR",
        // RFC 2230 §3: KX has DNS TYPE code 36.
        KX = 36 => "KX",
        // RFC 4398 §2: CERT is assigned RR type code 37.
        CERT = 37 => "CERT",
        // RFC 6672 §2.1: DNAME has resource record type code 39.
        DNAME = 39 => "DNAME",
        // RFC 6891 §6.1.1: OPT is RR type 41.
        OPT = 41 => "OPT",
        // RFC 3123 §3: APL is DNS type 42.
        APL = 42 => "APL",
        // RFC 4034 §5: DS RR type value is 43.
        DS = 43 => "DS",
        // RFC 4255 §3: The SSHFP resource-record type code is 44.
        SSHFP = 44 => "SSHFP",
        // RFC 4025 §1: IPSECKEY has DNS resource record type 45.
        IPSECKEY = 45 => "IPSECKEY",
        // RFC 4034 §3: RRSIG has type code 46 and is class independent.
        RRSIG = 46 => "RRSIG",
        // RFC 4034 §4: NSEC has RR type code 47.
        NSEC = 47 => "NSEC",
        // RFC 4034 §2: DNSKEY RR type value is 48.
        DNSKEY = 48 => "DNSKEY",
        // RFC 4701 §3: DHCID is DNS RR type 49.
        DHCID = 49 => "DHCID",
        // RFC 5155 §3: NSEC3 uses RR type code 50.
        NSEC3 = 50 => "NSEC3",
        NSEC3PARAM = 51 => "NSEC3PARAM",
        // RFC 6698 §7.1: TLSA uses DNS RR type code 52.
        TLSA = 52 => "TLSA",
        // RFC 8162 §8: SMIMEA uses DNS RRtype 53.
        SMIMEA = 53 => "SMIMEA",
        // RFC 8005 §9: HIP uses DNS RR type 55.
        HIP = 55 => "HIP",
        NINFO = 56 => "NINFO",
        RKEY = 57 => "RKEY",
        TALINK = 58 => "TALINK",
        // RFC 7344 §3.1: CDS uses DNS RR type code 59.
        CDS = 59 => "CDS",
        // RFC 7344 §3.2: CDNSKEY uses RR type code 60.
        CDNSKEY = 60 => "CDNSKEY",
        // RFC 7929 §8.1: OPENPGPKEY uses DNS RR type value 61.
        OPENPGPKEY = 61 => "OPENPGPKEY",
        // RFC 7477 §6: CSYNC has DNS RR type code 62.
        CSYNC = 62 => "CSYNC",
        // RFC 8976 §2: ZONEMD has DNS TYPE value 63.
        ZONEMD = 63 => "ZONEMD",
        // RFC 9460 §14.1: SVCB uses RR type code 64.
        SVCB = 64 => "SVCB",
        // RFC 9460 §14.2: HTTPS uses RR type code 65.
        HTTPS = 65 => "HTTPS",
        // RFC 4408 §12.1: SPF is assigned DNS RR and Qtype code 99.
        SPF = 99 => "SPF",
        UINFO = 100 => "UINFO",
        UID = 101 => "UID",
        GID = 102 => "GID",
        UNSPEC = 103 => "UNSPEC",
        // RFC 6742 §2.1: NID RR type value is 104.
        NID = 104 => "NID",
        // RFC 6742 §2.2: L32 RR type value is 105.
        L32 = 105 => "L32",
        // RFC 6742 §2.3: L64 RR type code is 106.
        L64 = 106 => "L64",
        // RFC 6742 §2.4: The LP RR type value is 107.
        LP = 107 => "LP",
        // RFC 7043 §3: EUI48 is RR type 108.
        EUI48 = 108 => "EUI48",
        // RFC 7043 §4: EUI64 has RR type value 109.
        EUI64 = 109 => "EUI64",
        // RFC 9824 §9: NXNAME is the allocated RR type code 128.
        NXNAME = 128 => "NXNAME",
        // RFC 2930 §2: TKEY RR type code is 249.
        TKEY = 249 => "TKEY",
        // RFC 8945 §3: TSIG resource record type code is 250.
        TSIG = 250 => "TSIG",
        // RFC 1995 §2: IXFR uses DNS QTYPE 251.
        IXFR = 251 => "IXFR",
        AXFR = 252 => "AXFR",
        MAILB = 253 => "MAILB",
        MAILA = 254 => "MAILA",
        ANY = 255 => "ANY",
        // RFC 7553 §4.1: URI is DNS RR type 256.
        URI = 256 => "URI",
        CAA = 257 => "CAA",
        AVC = 258 => "AVC",
        // RFC 8777 §5: AMTRELAY is assigned RR type 260.
        AMTRELAY = 260 => "AMTRELAY",
        // RFC 9606 §8.1: RESINFO uses DNS RR type code 261.
        RESINFO = 261 => "RESINFO",
        TA = 32768 => "TA",
        // RFC 4431 §4: IANA assigned DNS type code 32769 to DLV.
        DLV = 32769 => "DLV",
        RESERVED = 65535 => "Reserved",
    }
}
