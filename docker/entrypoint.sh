#!/bin/sh
set -u

mkdir -p /tmp/nginx-client /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi
mkdir -p /data/ravenguard

php-fpm &
FPM_PID=$!
nginx -c /etc/nginx/nginx.conf -g 'daemon off;' &
NGINX_PID=$!
# Run from the writable data volume, the default manual cert store resolves
# to ./data/manual-certs relative to the working directory.
(cd /data && exec ravenguard -config /etc/ravenguard/ravenguard.toml) &
RG_PID=$!

alive() {
	[ -d "/proc/$1" ] && [ "$(cut -d' ' -f3 "/proc/$1/stat" 2>/dev/null)" != "Z" ]
}

stop() {
	kill -TERM "$RG_PID" "$NGINX_PID" "$FPM_PID" 2>/dev/null
}

trap 'stop; wait; exit 0' TERM INT

while alive "$FPM_PID" && alive "$NGINX_PID" && alive "$RG_PID"; do
	sleep 1
done

stop
wait
exit 1
