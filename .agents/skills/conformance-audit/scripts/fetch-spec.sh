#!/usr/bin/env bash
# Fetch spec documents into a destination directory. Idempotent: existing files are kept.
# Usage: fetch-spec.sh <dest> <id>...   ids: RFC1035 | KEP-1645 | k8s-dns
# Outputs per id (paths printed to stdout):
#   RFC: rfcN.txt, rfcN.meta.json (updates, updated_by, obsoleted_by), rfcN.errata.json (non-rejected errata)
#   KEP: kep-N.md (README of the KEP, resolved under any SIG)
#   k8s-dns: k8s-dns-spec.md (Kubernetes DNS-Based Service Discovery spec)
set -euo pipefail

[ $# -ge 2 ] || { sed -n '3,7p' "$0" >&2; exit 2; }
dest=$1; shift
mkdir -p "$dest"

get() { [ -s "$2" ] || { curl -sfL --retry 3 "$1" -o "$2.$$" && mv "$2.$$" "$2"; }; }

fail=0
for raw in "$@"; do
  id=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -d ' _')
  case "$id" in
    rfc[0-9]*)
      n=$((10#${id#rfc}))
      get "https://www.rfc-editor.org/rfc/rfc$n.txt" "$dest/rfc$n.txt"
      get "https://www.rfc-editor.org/rfc/rfc$n.json" "$dest/rfc$n.meta.json"
      get "https://www.rfc-editor.org/errata.json" "$dest/.errata-all.json"
      [ -s "$dest/rfc$n.errata.json" ] || jq --arg d "RFC$n" \
        '[.[] | select(."doc-id" == $d and .errata_status_code != "Rejected")
             | {errata_id, status: .errata_status_code, type: .errata_type_code, section, orig_text, correct_text, notes}]' \
        "$dest/.errata-all.json" > "$dest/rfc$n.errata.json"
      printf '%s\n' "$dest/rfc$n.txt" "$dest/rfc$n.meta.json" "$dest/rfc$n.errata.json"
      ;;
    kep-[0-9]*|kep[0-9]*)
      n=$((10#${id##*[!0-9]}))
      [ -s "$dest/.kep-tree.txt" ] || gh api 'repos/kubernetes/enhancements/git/trees/master?recursive=1' \
        --jq '.tree[].path' > "$dest/.kep-tree.txt"
      path=$(grep -E "^keps/[^/]+/0*$n-[^/]+/README.md$" "$dest/.kep-tree.txt" | head -1 || true)
      if [ -z "$path" ]; then echo "fetch-spec: KEP-$n not found" >&2; fail=1; continue; fi
      get "https://raw.githubusercontent.com/kubernetes/enhancements/master/$path" "$dest/kep-$n.md"
      printf '%s\t%s\n' "$dest/kep-$n.md" "https://github.com/kubernetes/enhancements/blob/master/$path"
      ;;
    k8s-dns)
      get "https://raw.githubusercontent.com/kubernetes/dns/master/docs/specification.md" "$dest/k8s-dns-spec.md"
      printf '%s\n' "$dest/k8s-dns-spec.md"
      ;;
    *) echo "fetch-spec: unknown id '$raw'" >&2; fail=1 ;;
  esac
done
exit $fail
