# DNS wire corpus

Each `.bin` file is one complete DNS wire message, without TCP length framing.
The bytes are copied unchanged from the indicated upstream test literals (hex
strings are decoded to bytes). They are test vectors, not necessarily captured
network traffic.

## CoreDNS

Repository: https://github.com/coredns/coredns

Revision: `v1.15.0` (`a6fde3fe339c6ec848447e11cc9796be8c97b4e0`)

License: Apache-2.0 ([LICENSE](https://github.com/coredns/coredns/blob/v1.15.0/LICENSE))

| File | Original test location | Description |
| --- | --- | --- |
| `coredns-doh-query.bin` | [`core/dnsserver/https_test.go`, `TestDoHWriter_Write`, `valid DNS message`](https://github.com/coredns/coredns/blob/v1.15.0/core/dnsserver/https_test.go#L92-L115) | A query for `www.example.com.` |

## miekg/dns

Repository: https://github.com/miekg/dns

Revision: `b2d6c9f4480a71247e0df4ce709122852a2849cf`

License: BSD-3-Clause ([LICENSE](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/LICENSE))

| File | Original test location | Description |
| --- | --- | --- |
| `miekg-soa-response.bin` | [`dns_test.go`, `TestMsgPackBuffer`, `testMessages[0]`](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/dns_test.go#L241-L260) | Negative response with compressed SOA authority record |
| `miekg-a-query.bin` | [`dns_test.go`, `TestMsgPackBuffer`, `testMessages[1]`](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/dns_test.go#L241-L260) | A query corresponding to the SOA response |
| `miekg-servfail-response.bin` | [`dns_test.go`, `TestMsgPackBuffer`, `testMessages[2]`](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/dns_test.go#L241-L260) | SERVFAIL response |
| `miekg-edns-esu.bin` | [`edns_test.go`, `TestEDNS0_ESU`, `p`](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/edns_test.go#L197-L210) | EDNS Source URI option |
| `miekg-dynamic-update.bin` | [`update_test.go`, `TestDynamicUpdateUnpack`, `buf`](https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/update_test.go#L35-L45) | Dynamic update deleting and adding an A record |
| `tsig-miekg.txt` | miekg/dns v1.1.73 `TsigGenerate` and `TsigGenerateWithProvider` | Hex TSIG Query, first Response, and subsequent Response, at time 1594855491, fudge 300, key `testkey.`, secret `NoTCJU+DMqFWywaPyxSijrDEA/eC3nK0xi3AMEZuPVk=`. Each triple has the algorithm, wire Message and MAC. MD5 uses a Go HMAC-MD5 provider because miekg's default provider no longer implements it. |

RFC 8945 has no Appendix A or published test vectors; the signed fixture in
`tests/tsig.rs` is from miekg/dns `TestTsigErrors`.

See `THIRD_PARTY_NOTICES` at the repository root for attribution and license terms.
