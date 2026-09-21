;<?php http_response_code(403); /*
; PrivateBin configuration for the container image.
; Mount your own file over /srv/privatebin/cfg/conf.php to customize.
; All options: https://github.com/PrivateBin/PrivateBin/wiki/Configuration

[main]
discussion = true
password = true
fileupload = false
sizelimit = 10000000

; RavenGuard rebuilds X-Forwarded-For, so the traffic limiter can trust it
[traffic]
header = "X_FORWARDED_FOR"

[model]
class = Filesystem

[model_options]
; paste storage lives outside the web root, on the /data volume
dir = "/data"
