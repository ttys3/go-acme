#!/bin/sh

set -e

go build ./cmd/auto-acme

ACME_ROOT_DIR=/tmp/acme

CF_DNS_API_TOKEN="-xxxxxxxxxxx"

test -d ${ACME_ROOT_DIR} || mkdir -p ${ACME_ROOT_DIR}

curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer ${CF_DNS_API_TOKEN}" \
     -H "Content-Type:application/json" && \
env HTTP_PROXY=http://127.0.0.1:7070 \
GO_ACME_KEY_PATH=${ACME_ROOT_DIR}/foo.key \
GO_ACME_CERT_PATH=${ACME_ROOT_DIR}/foo.crt \
GO_ACME_STORAGE_DIR=${ACME_ROOT_DIR} \
AUTOCERT_EMAIL=foo@outlook.com \
AUTOCERT_DOMAIN=ttys3.net \
AUTOCERT_DNS_PROVIDER=cloudflare \
CF_DNS_API_TOKEN="${CF_DNS_API_TOKEN}" ./auto-acme -test -interval 30 --cmd "date >> /tmp/acme.txt"

