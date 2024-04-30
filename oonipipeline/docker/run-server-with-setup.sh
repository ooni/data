#!/usr/bin/env bash
set -ex

echo "starting superset"

if [ ! -f /var/run/superset/superset_is_configured ]; then
    echo "superset is not configured, setting it up"
    superset fab create-admin \
                --username admin \
                --firstname OONI \
                --lastname Tarian \
                --email admin@ooni.org \
                --password oonity
    superset db upgrade
    superset init
    touch /var/run/superset/superset_is_configured
fi
/usr/bin/run-server.sh