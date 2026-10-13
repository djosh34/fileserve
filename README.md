# fileserve

A tiny standard-library Go HTTPS server that streams one file to allowed mTLS clients.

## Run

Build with Go 1.27.2 (`go build -o fileserve .`), or download
[`fileserve-linux-amd64` or `fileserve-linux-arm64`](https://github.com/djosh34/fileserve/releases/tag/v0.1.0)
and `chmod +x` the binary. Both Linux release binaries use `CGO_ENABLED=0`.

With your CA, server certificate/key and client certificate/key:

```sh
./fileserve --allow 'alice,bob' --file ./payload.bin \
  --cacert ./client-ca.pem --cert ./server.pem --key ./server.key \
  --listen :8443
curl --fail --cacert ./server-ca.pem --cert ./alice.pem --key ./alice.key \
  https://localhost:8443 -o downloaded.bin
```

All flags except `--listen` are required; the default address is `:8443`.
`--help` lists them. The server certificate must have the appropriate SAN
(e.g. `localhost`). Clients need a trusted clientAuth certificate. After normal
TLS chain verification, only the verified client leaf's Common Name is matched
against the comma-separated `--allow` list. Entries are trimmed and cannot be
empty. Matching is exact and case-sensitive: no wildcards, SAN/issuer fallback,
Host checks or address policy. Disallowed clients fail the TLS handshake.

Only GET `/` serves bytes; root queries are ignored. Other methods/paths that
reach the handler return 404, with Go's default `OPTIONS *` handling unchanged.
There are no redirects, directory listing, HEAD support or range responses.

The regular file is opened once at startup. A mutex serializes complete
seek-to-zero/stream-to-EOF transfers; concurrent requests wait. No snapshot or
per-request reopen is used. Changes to that open file can affect later/current
reads; replace the file and **restart** to select the replacement. Failed
streams are logged and aborted rather than presented as complete downloads.

## Scratch image

CI publishes `ghcr.io/djosh34/fileserve:v0.1.0` and `:latest` for Linux amd64
and arm64. The image is `FROM scratch` with one binary COPY, no shell or
bundled certificates. Package visibility may initially be private; authenticate
with GHCR if needed. Mount the payload and certificates:

```sh
docker run --rm -p 8443:8443 \
  -v "$PWD/payload.bin:/data:ro" \
  -v "$PWD/client-ca.pem:/client-ca.pem:ro" \
  -v "$PWD/server.pem:/server.pem:ro" \
  -v "$PWD/server.key:/server.key:ro" \
  ghcr.io/djosh34/fileserve:v0.1.0 \
  --allow alice --file /data --cacert /client-ca.pem \
  --cert /server.pem --key /server.key
```

## Checks

```sh
go test -race ./...
go build -o fileserve . && bash test-curl.sh ./fileserve
golangci-lint run
```

Use golangci-lint 2.14.0. CI runs these as `test`, `curl`, and `lint` on PRs
and main. Tests generate temporary certificates; no private keys are committed.
