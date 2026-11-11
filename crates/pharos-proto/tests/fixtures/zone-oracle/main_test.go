package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParse(t *testing.T) {
	got := string(parse([]byte("a 60 IN TXT \"\\000\\255\"\n"), "example."))
	want := "accept\n0161076578616d706c6500\t60\t1\t16\t0200ff\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := string(parse([]byte("a IN A invalid\n"), "example.")); got != "reject\n" {
		t.Fatalf("invalid zone: %q", got)
	}
}

func TestPackErrorIsNotRejection(t *testing.T) {
	rr := &dns.A{Hdr: dns.RR_Header{Name: strings.Repeat("a", 64) + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}
	got := string(pack([]dns.RR{rr}))
	if !strings.HasPrefix(got, "pack_error\nPackRR: ") {
		t.Fatalf("packing failure was hidden: %q", got)
	}
	zone := "a 60 IN TXT " + strings.Repeat("\""+strings.Repeat("x", 255)+"\" ", 260)
	got = string(parse([]byte(zone), "example."))
	if !strings.HasPrefix(got, "pack_error\nPackRR: ") {
		t.Fatalf("oversized parsed RR packing failure was hidden: %q", got)
	}
}
