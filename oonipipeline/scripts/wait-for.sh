#!/bin/sh

set -e

host="$1"
shift
cmd="$@"

until wget --spider --quiet $host > /dev/null; do
  >&2 echo "Waiting for $host to become available..."
  sleep 1
done

>&2 echo "$host is up - executing command $cmd"
exec $cmd
