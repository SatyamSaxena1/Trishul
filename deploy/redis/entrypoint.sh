#!/bin/sh
set -eu

password_hash="$(sha256sum /run/secrets/redis_password | cut -d ' ' -f 1)"
printf 'user default on #%s ~* &* +@all\n' "$password_hash" > /run/redis/users.acl
exec redis-server --appendonly yes --aclfile /run/redis/users.acl --dir /data

