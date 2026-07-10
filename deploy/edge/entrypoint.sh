#!/bin/sh
set -eu

printf '%s' "${OIDC_BROWSER_ORIGIN:-}" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?$' \
    || { printf 'OIDC_BROWSER_ORIGIN must be an HTTPS origin without a path\n' >&2; exit 1; }
envsubst '${OIDC_BROWSER_ORIGIN}' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
