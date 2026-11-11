// Zone-file oracle using a local github.com/miekg/dns checkout.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/miekg/dns"
)

func parse(zone []byte, origin string) []byte {
	parser := dns.NewZoneParser(bytes.NewReader(zone), origin, "live.zone")
	var records []dns.RR
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		records = append(records, rr)
	}
	if parser.Err() != nil {
		return []byte("reject\n")
	}
	return pack(records)
}

func pack(records []dns.RR) []byte {
	var result bytes.Buffer
	result.WriteString("accept\n")
	for _, rr := range records {
		h := rr.Header()
		// RFC 1035 §4.1.3: compare each record's uncompressed wire fields.
		wire := make([]byte, 65535)
		end, err := dns.PackRR(rr, wire, 0, nil, false)
		if err != nil {
			return []byte(fmt.Sprintf("pack_error\nPackRR: %v\n", err))
		}
		ownerEnd, err := dns.PackDomainName(h.Name, wire, 0, nil, false)
		if err != nil {
			return []byte(fmt.Sprintf("pack_error\nPackDomainName: %v\n", err))
		}
		if ownerEnd+10 > end {
			return []byte("pack_error\nshort packed RR\n")
		}
		fmt.Fprintf(&result, "%x\t%d\t%d\t%d\t%x\n", wire[:ownerEnd], h.Ttl, h.Class, h.Rrtype, wire[ownerEnd+10:end])
	}
	return result.Bytes()
}

func readFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	return data, err
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--batch" {
		reader, writer := bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout)
		for {
			origin, err := readFrame(reader)
			if err == io.EOF {
				return writer.Flush()
			}
			if err != nil {
				return err
			}
			zone, err := readFrame(reader)
			if err != nil {
				return err
			}
			result := parse(zone, string(origin))
			if err := binary.Write(writer, binary.BigEndian, uint32(len(result))); err != nil {
				return err
			}
			if _, err := writer.Write(result); err != nil {
				return err
			}
		}
	}
	if len(os.Args) > 2 {
		return fmt.Errorf("usage: zone-oracle [origin|--batch]")
	}
	origin := "."
	if len(os.Args) == 2 {
		origin = os.Args[1]
	}
	zone, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(parse(zone, origin))
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
