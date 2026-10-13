#!/usr/bin/env bash
set -euo pipefail
binary=$(realpath "${1:-./fileserve}")
tmp=$(mktemp -d)
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
cd "$tmp"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj /CN=test-ca > /dev/null 2>&1
issue() {
  local name=$1 cn=$2 usage=$3 san=$4 ca=${5:-ca}
  openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$cn" > /dev/null 2>&1
  printf 'extendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' "$usage" "$san" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" > /dev/null 2>&1
}
issue server localhost serverAuth localhost
issue allowed alice clientAuth unrelated
issue denied bob clientAuth alice
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 1 -subj /CN=other-ca > /dev/null 2>&1
issue untrusted alice clientAuth alice other
dd if=/dev/urandom of=data bs=1024 count=128 status=none
port=$((20000 + RANDOM))
url="https://localhost:$port"
"$binary" --allow ' alice ' --file data --cacert ca.pem --cert server.pem --key server.key --listen "127.0.0.1:$port" > server.log 2>&1 &
pid=$!
base=(--silent --show-error --max-time 5 --noproxy '*' --cacert ca.pem)
auth=(--cert allowed.pem --key allowed.key)
ready=false
for ((i=0; i<50; i++)); do
  if curl "${base[@]}" "${auth[@]}" --fail "$url" -o received 2>/dev/null; then ready=true; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then printf 'Server did not become ready\n' >&2; while IFS= read -r line; do printf '%s\n' "$line" >&2; done < server.log; exit 1; fi
for path in '' '/' '/?ignored=yes'; do
  curl "${base[@]}" "${auth[@]}" --fail "$url$path" -o received
  cmp data received
done
for request in 'GET /other' 'HEAD /' 'POST /'; do
  read -r method path <<< "$request"
  options=(-X "$method")
  if [[ "$method" == HEAD ]]; then options=(--head); fi
  status=$(curl "${base[@]}" "${auth[@]}" "${options[@]}" -o /dev/null -w '%{http_code}' "$url$path")
  [[ "$status" == 404 ]] || { printf '%s: expected 404, got %s\n' "$request" "$status" >&2; exit 1; }
done
for name in missing denied untrusted; do
  cert=()
  if [[ "$name" != missing ]]; then cert=(--cert "$name.pem" --key "$name.key"); fi
  if curl "${base[@]}" "${cert[@]}" "$url/" -o /dev/null 2>/dev/null; then
    printf 'TLS unexpectedly accepted %s client\n' "$name" >&2; exit 1
  fi
done
printf 'curl checks passed\n'
