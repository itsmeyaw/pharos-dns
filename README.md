# Pharos

Pharos is a performance-first Rust DNS server and a Corefile-compatible successor to CoreDNS v1.15.0.

Migrating from CoreDNS? See the [migration guide](MIGRATION.md) and
[compatibility document](docs/compatibility.md).

## Container image

Build for the host with Docker Buildx, Cargo and Python 3 (or use
`--platform linux/amd64,linux/arm64` and push or export the multi-platform image):

```sh
version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "pharos-dns"))')
docker buildx build --load -t pharos:local \
  --build-arg VERSION="$version" --build-arg REVISION="$(git rev-parse HEAD)" .
```

The image runs as UID/GID 65532 with a read-only root filesystem supported.
For an example Kubernetes installation see `deploy/kubernetes/pharos.yaml`.

## Kubernetes end-to-end test

`cargo xtask e2e` needs Docker Buildx with Linux containers, kind and kubectl. It
builds the host image, creates a `pharos-e2e` kind cluster, compares stock
CoreDNS with an in-place Pharos migration, checks probes and Reload, and
deletes the cluster on exit. It refuses to replace an existing cluster with
that name. Use `cargo xtask e2e --keep` to retain it and its kubeconfig for
debugging. Normalized baseline answers are saved in `target/e2e/coredns.txt`.
The test requires access to public container registries and DNS.
For a source snapshot without Git metadata, set `PHAROS_IMAGE_REVISION` to the
source commit for the image's revision label.
After an interrupted run, remove any remaining cluster with
`kind delete cluster --name pharos-e2e`.
