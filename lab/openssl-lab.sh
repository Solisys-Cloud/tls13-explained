#!/usr/bin/env bash
# Written by Olivier Lumeau
# https://github.com/Solisys-Cloud/tls13-explained
# TLS 1.3 lab with openssl (Linux, macOS, WSL or Git Bash on Windows)
# Usage: ./openssl-lab.sh www.solisys.be
# Read-only: it only opens TLS connections.

set -u
HOST="${1:-www.solisys.be}"
PORT="${2:-443}"

echo "== 1. Summary: version, cipher suite, ECDHE group, certificate =="
openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1_3 -brief </dev/null 2>&1 | head -12

echo
echo "== 2. The handshake messages, one by one =="
openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1_3 -msg </dev/null 2>&1 \
  | grep -E '^(>>>|<<<).*(ClientHello|ServerHello|EncryptedExtensions|Certificate|CertificateVerify|Finished)'

echo
echo "== 3. Certificate chain: subject (s) and issuer (i) =="
openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -showcerts </dev/null 2>/dev/null \
  | grep -E '^ ?[0-9]+ s:|^ +i:'

echo
echo "== 4. Does the server still accept TLS 1.1? (expect an error) =="
openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 \
  | grep -E 'alert|error|Protocol' | head -3

echo
echo "== 5. Export the session secrets for Wireshark (file: ./keys.log) =="
openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1_3 -keylogfile ./keys.log </dev/null >/dev/null 2>&1
grep -oE '^[A-Z_0-9]+' ./keys.log | sort -u
echo "Wireshark: Preferences > Protocols > TLS > (Pre)-Master-Secret log filename = $(pwd)/keys.log"
echo "Delete keys.log after the lab: anyone holding it can decrypt the captured session."
