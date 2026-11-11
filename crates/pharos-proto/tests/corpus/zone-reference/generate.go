// Regenerate static fixtures from a local miekg/dns checkout; see README.md.
package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: generate.go <fixture-directory>")
	}
	dir := os.Args[1]
	var octets bytes.Buffer
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&octets, "n%d.example. 1 IN TXT \"\\%03d\"\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(dir, "octets.zone"), octets.Bytes(), 0644); err != nil {
		panic(err)
	}
	// RFC 1035 §5.1: vary record whitespace, class/TTL order and escaped text octets.
	random := rand.New(rand.NewSource(46))
	var seeded bytes.Buffer
	for i := 0; i < 512; i++ {
		fmt.Fprintf(&seeded, "f%d", i)
		if random.Intn(2) == 0 {
			fmt.Fprintf(&seeded, "\tIN %d TXT \"", random.Intn(86400))
		} else {
			fmt.Fprintf(&seeded, "  %d IN TXT \"", random.Intn(86400))
		}
		for j, n := 0, random.Intn(16); j < n; j++ {
			fmt.Fprintf(&seeded, "\\%03d", random.Intn(256))
		}
		fmt.Fprintln(&seeded, "\" ; seeded case")
	}
	if err := os.WriteFile(filepath.Join(dir, "seeded.zone"), seeded.Bytes(), 0644); err != nil {
		panic(err)
	}
	for _, test := range []struct{ file, origin string }{
		{"miekg", "."},
		{"coredns", "example.org."},
		{"coredns-escape", "campus.edu."},
		{"octets", "example."},
		{"seeded", "example."},
	} {
		data, err := os.ReadFile(filepath.Join(dir, test.file+".zone"))
		if err != nil {
			panic(err)
		}
		parser := dns.NewZoneParser(bytes.NewReader(data), test.origin, test.file+".zone")
		var output bytes.Buffer
		for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
			h := rr.Header()
			wire := make([]byte, 65535)
			end, err := dns.PackRR(rr, wire, 0, nil, false)
			if err != nil {
				panic(err)
			}
			ownerEnd, err := dns.PackDomainName(h.Name, wire, 0, nil, false)
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(&output, "%x\t%d\t%d\t%d\t%x\n", wire[:ownerEnd], h.Ttl, h.Class, h.Rrtype, wire[ownerEnd+10:end])
		}
		if err := parser.Err(); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(dir, test.file+".expected"), output.Bytes(), 0644); err != nil {
			panic(err)
		}
	}
}
