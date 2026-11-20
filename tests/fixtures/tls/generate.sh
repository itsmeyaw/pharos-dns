#!/bin/sh
# Regenerates the TLS test fixtures. Test-only keys: never use them elsewhere.
set -eu
cd "$(dirname "$0")"
DAYS=36500
ca() { # name subject
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days $DAYS \
    -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$1.key.tmp" -out "$1.pem"
}
leaf() { # name subject ca usage san
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$2" \
    -keyout "$1.key.pem" -out "$1.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\n%s\n' "$4" "$5" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key.tmp" -CAcreateserial -days $DAYS \
    -extfile "$1.ext" -out "$1.pem"
  rm "$1.csr" "$1.ext"
}
SAN='subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'
ca ca "Pharos test CA"
ca other-ca "Pharos other test CA"
leaf server localhost ca serverAuth "$SAN"
leaf server-renewed localhost ca serverAuth "$SAN"
leaf client "pharos test client" ca clientAuth ""
leaf rogue-client "pharos rogue client" other-ca clientAuth ""
rm -f ./*.key.tmp ./*.srl
