#!/bin/sh
set -eu

[ "$#" -eq 3 ] || { echo "usage: run-zap.sh STAGING_ORIGIN COMMIT_SHA VERSION_ID" >&2; exit 2; }
target="${1%/}"
commit="$2"
version="$3"
case "$target" in
    https://*[!A-Za-z0-9._:/-]*) echo "staging origin contains unsupported characters" >&2; exit 2 ;;
    https://*) ;;
    *) echo "staging origin must use HTTPS" >&2; exit 2 ;;
esac
echo "$commit" | grep -Eq '^[0-9a-f]{40,64}$' || { echo "invalid commit SHA" >&2; exit 2; }

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
sed "s|__TARGET__|$target|" "$root/deploy/ci/zap-safe-plan.yaml" > "$work/plan.yaml"
image="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2}"
case "$image" in *@sha256:*) ;; *) echo "ZAP_IMAGE must be pinned by digest" >&2; exit 2 ;; esac

timeout 30m docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=512m --tmpfs /home/zap/.ZAP:rw,noexec,nosuid,size=512m \
    -v "$work:/zap/wrk:rw" "$image" zap.sh -cmd -autorun /zap/wrk/plan.yaml
python "$root/scripts/trishul_ci_bundle.py" zap "$work/zap.json" "$work/bundle.json" \
    --commit "$commit" --target "$target"
TRISHUL_VERSION_ID="$version" python "$root/scripts/trishul_ci_upload.py" "$work/bundle.json"
