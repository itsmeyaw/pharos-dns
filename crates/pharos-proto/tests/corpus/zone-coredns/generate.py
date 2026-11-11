#!/usr/bin/env python3
"""Extract CoreDNS zones and run the existing miekg/dns oracle offline."""
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

if len(sys.argv) != 3:
    sys.exit("usage: generate.py <coredns-checkout> <miekg-dns-checkout>")

coredns, miekg = map(Path, sys.argv[1:])
directory = Path(__file__).resolve().parent
oracle = directory.parent.parent / "fixtures/zone-oracle/main.go"
cases = re.findall(r'^\s*(\w+) => "([^"]+)",', (directory / "manifest.rs").read_text(), re.M)
if not cases or len(cases) != len({name for name, _ in cases}):
    raise ValueError("empty manifest or duplicate fixture names")
fixtures = {}
for path in sorted((coredns / "plugin/file").glob("*_test.go")):
    text = path.read_text()
    for match in re.finditer(r'const\s+(\w+)\s*=\s*`([^`]*)`', text, re.S):
        name, data = match.groups()
        if "\n" in data:
            if name in fixtures:
                raise ValueError(f"duplicate fixture {name}")
            fixtures[name] = data

def raw(file, expression):
    text = (coredns / "plugin/file" / file).read_text()
    matches = re.findall(expression + r'\s*`([^`]*)`', text, re.S)
    if len(matches) != 1:
        raise ValueError(f"expected one raw fixture in {file}, found {len(matches)}")
    return matches[0]

fixtures["laterSOAOrigin"] = raw("file_test.go", r'zone\s*:=')
fixtures["includeZone"] = raw("include_test.go", r'zone\s*:=') + "child.zone\n"
template = raw("setup_test.go", r'contents\s*:=\s*fmt\.Sprintf\(')
for name, owner in [("setupSOARelative", "test"), ("setupSOAAt", "@"), ("setupSOAAbsolute", "test.")]:
    fixtures[name] = template.replace("%s", owner)
fixtures["dbRelativeNet"] = fixtures["dbRelative"]

if set(fixtures) != {name for name, _ in cases}:
    raise ValueError(f"fixture/test mismatch: {set(fixtures) ^ {name for name, _ in cases}}")

def frame(data):
    return struct.pack(">I", len(data)) + data

request = b"".join(frame(origin.encode()) + frame(fixtures[name].encode()) for name, origin in cases)
env = {**os.environ, "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}
response = subprocess.run(["go", "run", str(oracle), "--batch"], cwd=miekg, env=env, input=request, stdout=subprocess.PIPE, check=True).stdout
offset = 0
for name, _ in cases:
    if offset + 4 > len(response):
        raise ValueError(f"missing oracle response for {name}")
    length = struct.unpack_from(">I", response, offset)[0]
    offset += 4
    result = response[offset:offset + length]
    if len(result) != length or not (result.startswith(b"accept\n") or result == b"reject\n"):
        raise ValueError(f"invalid oracle response for {name}: {result!r}")
    (directory / f"{name}.zone").write_text(fixtures[name])
    (directory / f"{name}.expected").write_bytes(result)
    offset += length
if offset != len(response):
    raise ValueError("unexpected trailing oracle response")
