# hosts

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/hosts/README.md)

## hosts

- Pharos discards names that are not valid DNS names or UTF-8; CoreDNS retains arbitrary fields in its hosts maps.
- Pharos lowercases ASCII name bytes, while CoreDNS applies Go's Unicode lowercasing.
- Configured Domains that cannot be represented as DNS names are ignored for matching; CoreDNS keeps its normalized strings.
- On a file read error, an unfinished field is discarded; CoreDNS processes the last partial chunk before logging the error.
- Responses require a preallocated UDP buffer, as with Whoami.
- Hosts-file reloads stop during configuration Restart and resume if that Restart fails.
- File parsing runs on a Tokio worker, so a large or slow hosts file can delay other tasks on that worker.

## Sources

- CoreDNS plugin/hosts/hosts_test.go hostsExample.
