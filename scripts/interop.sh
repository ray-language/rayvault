#!/bin/sh
# rayvault with real pieces: a fresh rayauth as the issuer (two service accounts, one with the
# vault scope and one without), a TLS certificate from a CA made with openssl that the clients
# trust through SSL_CERT_FILE, and the rayvault CLI getting its token by client credentials.
# Usage: scripts/interop.sh [RAYAUTH_BINARY]   (needs ./rayvault: make build; default
# ../rayauth/rayauth)
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/rayvault"
RAYAUTH="${1:-$HERE/../rayauth/rayauth}"
[ -x "$RAYAUTH" ] || { echo "interop: no rayauth binary at $RAYAUTH" >&2; exit 1; }
command -v openssl >/dev/null || { echo "interop: needs openssl" >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rayvault-interop.XXXXXX")"
RA=$((40000 + $(od -An -N2 -tu2 /dev/urandom) % 10000))
RV=$((50000 + $(od -An -N2 -tu2 /dev/urandom) % 10000))
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
wait_http() { i=0; until curl -sk -o /dev/null "$1"; do i=$((i + 1)); [ $i -gt 50 ] && return 1; sleep 0.2; done; }

# rayauth, with two service accounts.
export RAYAUTH_ISSUER="http://localhost:$RA" RAYAUTH_PORT="$RA" RAYAUTH_DATA_DIR="$WORK/rayauth" RAYAUTH_DEV=true
echo 'root password 123' | "$RAYAUTH" create-admin root >/dev/null
API_TOKEN=$("$RAYAUTH" create-api-token root interop --days 1)
"$RAYAUTH" >"$WORK/rayauth.log" 2>&1 &
PIDS="$PIDS $!"
wait_http "$RAYAUTH_ISSUER/-/health" || { cat "$WORK/rayauth.log"; exit 1; }
client() {
    curl -sf -X POST -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
        "$RAYAUTH_ISSUER/api/v1/clients" -d "{\"name\":\"$1\",\"grant_types\":[\"client_credentials\"],\"scopes\":[\"$2\"]}"
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }
JOB=$(client vault-job vault); JOB_ID=$(echo "$JOB" | field client_id); JOB_SECRET=$(echo "$JOB" | field client_secret)
OTHER=$(client other-job notes.read); OTHER_ID=$(echo "$OTHER" | field client_id); OTHER_SECRET=$(echo "$OTHER" | field client_secret)

# A CA of our own, and a certificate for 127.0.0.1 signed by it (rustls refuses a self-signed
# CA certificate used as the server's own: CaUsedAsEndEntity). The clients trust the CA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=rayvault-interop-ca -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=127.0.0.1 \
    -keyout "$WORK/key.pem" -out "$WORK/server.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$WORK/ext.cnf"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 1 -extfile "$WORK/ext.cnf" -out "$WORK/cert.pem" 2>/dev/null
cat >"$WORK/rayvault.toml" <<EOF
[server]
listen = "127.0.0.1:$RV"
data = "$WORK/vault"
tls_cert = "$WORK/cert.pem"
tls_key = "$WORK/key.pem"
issuer = "$RAYAUTH_ISSUER"
scope = "vault"

[[policy]]
subject = "client:$JOB_ID"
paths = ["apps/notes/*"]
caps = ["read", "list", "wrap"]
EOF
"$BIN" serve --config "$WORK/rayvault.toml" >"$WORK/rayvault.log" 2>&1 &
PIDS="$PIDS $!"
wait_http "https://127.0.0.1:$RV/v1/sys/status" || { cat "$WORK/rayvault.log"; exit 1; }

export SSL_CERT_FILE="$WORK/ca.pem" RAYVAULT_ADDR="https://127.0.0.1:$RV"
pass=0
check() { name=$1; shift
    if "$@" >"$WORK/out" 2>&1; then pass=$((pass + 1)); printf "  ok    %s\n" "$name"
    else printf "  FAIL  %s\n" "$name"; sed 's/^/        /' "$WORK/out"; exit 1; fi; }
fails() { name=$1; want=$2; shift 2
    if "$@" >"$WORK/out" 2>&1; then printf "  FAIL  %s (succeeded)\n" "$name"; exit 1; fi
    if grep -q -- "$want" "$WORK/out"; then pass=$((pass + 1)); printf "  ok    %s\n" "$name"
    else printf "  FAIL  %s\n" "$name"; sed 's/^/        /' "$WORK/out"; exit 1; fi; }
as_job() { env RAYVAULT_ISSUER="$RAYAUTH_ISSUER" RAYVAULT_CLIENT_ID="$JOB_ID" RAYVAULT_CLIENT_SECRET="$JOB_SECRET" "$@"; }
as_other() { env RAYVAULT_ISSUER="$RAYAUTH_ISSUER" RAYVAULT_CLIENT_ID="$OTHER_ID" RAYVAULT_CLIENT_SECRET="$OTHER_SECRET" RAYVAULT_SCOPE="$OTHER_SCOPE" "$@"; }

echo "rayvault interop: rayauth on $RAYAUTH_ISSUER, rayvault on $RAYVAULT_ADDR (TLS, own CA)"
fails "TLS without trusting the certificate" "certificate" env -u SSL_CERT_FILE "$BIN" status
check "status: not initialized" sh -c "'$BIN' status | grep -q 'initialized: false'"
ROOT=$(RAYVAULT_PASSPHRASE='correct horse battery staple' "$BIN" init 2>/dev/null)
check "init gives a root token" sh -c "echo '$ROOT' | grep -q '^rvr_'"
check "root writes" env RAYVAULT_TOKEN="$ROOT" "$BIN" put apps/notes/db 'postgres://notes:s3cr3t@db/notes'
check "root writes elsewhere" env RAYVAULT_TOKEN="$ROOT" "$BIN" put apps/web/tls 'pem bytes'
check "the job is client:<its id>" sh -c "$(printf '%s' "env RAYVAULT_ISSUER=$RAYAUTH_ISSUER RAYVAULT_CLIENT_ID=$JOB_ID RAYVAULT_CLIENT_SECRET=$JOB_SECRET '$BIN' whoami") | grep -q 'client:$JOB_ID'"
check "the job reads with a rayauth token" sh -c "$(printf '%s' "env RAYVAULT_ISSUER=$RAYAUTH_ISSUER RAYVAULT_CLIENT_ID=$JOB_ID RAYVAULT_CLIENT_SECRET=$JOB_SECRET '$BIN' get apps/notes/db") | grep -q s3cr3t"
check "the job lists its folder" sh -c "$(printf '%s' "env RAYVAULT_ISSUER=$RAYAUTH_ISSUER RAYVAULT_CLIENT_ID=$JOB_ID RAYVAULT_CLIENT_SECRET=$JOB_SECRET '$BIN' ls apps/notes") | grep -qx db"
fails "the job cannot write" "403" as_job "$BIN" put apps/notes/db mine
fails "the job cannot read another folder" "403" as_job "$BIN" get apps/web/tls
OTHER_SCOPE=vault fails "rayauth refuses the vault scope to an account without it" "invalid_scope" as_other "$BIN" get apps/notes/db
OTHER_SCOPE=notes.read fails "rayvault refuses a token without the vault scope" "401" as_other "$BIN" get apps/notes/db
WRAP=$(as_job "$BIN" wrap apps/notes/db --ttl 1m)
check "a wrap token, unwrapped with no credentials" sh -c "'$BIN' unwrap '$WRAP' | grep -q s3cr3t"
fails "a wrap token works once" "404" "$BIN" unwrap "$WRAP"
fails "only root seals" "403" as_job "$BIN" seal
check "root seals" env RAYVAULT_TOKEN="$ROOT" "$BIN" seal
fails "sealed: nothing reads" "503" as_job "$BIN" get apps/notes/db
fails "a wrong passphrase" "403" env RAYVAULT_PASSPHRASE='not the passphrase at all' "$BIN" unseal
check "unseal" env RAYVAULT_PASSPHRASE='correct horse battery staple' "$BIN" unseal
check "readable again" sh -c "$(printf '%s' "env RAYVAULT_ISSUER=$RAYAUTH_ISSUER RAYVAULT_CLIENT_ID=$JOB_ID RAYVAULT_CLIENT_SECRET=$JOB_SECRET '$BIN' get apps/notes/db") | grep -q s3cr3t"
check "the audit chain holds" "$BIN" audit verify "$WORK/vault/audit.log"
check "no secret in the audit log" sh -c "! grep -q s3cr3t '$WORK/vault/audit.log'"
check "no plaintext in the database" sh -c "! grep -aq s3cr3t '$WORK/vault/vault.db'"
echo "$pass checks passed"
