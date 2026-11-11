package main

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strconv"
	"strings"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		at := strings.Index(line, "PHAROS_SIGN_VECTOR ")
		if at < 0 {
			continue
		}
		fields := strings.Fields(line[at:])
		alg, err := strconv.Atoi(fields[1])
		if err != nil {
			panic(err)
		}
		tag, err := strconv.Atoi(fields[2])
		if err != nil {
			panic(err)
		}
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 256, Protocol: 3, Algorithm: uint8(alg), PublicKey: fields[3]}
		r := &dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeA, Algorithm: uint8(alg), Labels: 3, OrigTtl: 300, Expiration: 2000000000, Inception: 1600000000, KeyTag: uint16(tag), SignerName: "example.org.", Signature: fields[4]}
		rr, err := dns.NewRR("www.example.org. 300 IN A 192.0.2.1")
		if err != nil {
			panic(err)
		}
		if err := r.Verify(k, []dns.RR{rr}); err != nil {
			panic(fmt.Sprintf("algorithm %d: %v", alg, err))
		}
		altered, err := dns.NewRR("www.example.org. 300 IN A 192.0.2.2")
		if err != nil {
			panic(err)
		}
		if err := r.Verify(k, []dns.RR{altered}); err == nil {
			panic(fmt.Sprintf("algorithm %d accepted altered RRset", alg))
		}
		fmt.Printf("algorithm %d verified; altered RRset rejected\n", alg)
		count++
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	if count != 5 {
		panic(fmt.Sprintf("expected 5 vectors, got %d", count))
	}
}
