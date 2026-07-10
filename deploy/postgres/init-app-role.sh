#!/bin/sh
set -eu

app_password="$(cat /run/secrets/db_app_password)"
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=app_password="$app_password" <<-'SQL'
    CREATE ROLE trishul_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'app_password';
    GRANT CONNECT ON DATABASE trishul TO trishul_app;
SQL

