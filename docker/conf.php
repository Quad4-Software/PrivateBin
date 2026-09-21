;<?php http_response_code(403); /*
; PrivateBin configuration for the container image.
; Mount your own file over /srv/privatebin/cfg/conf.php to customize.
; All options: https://github.com/PrivateBin/PrivateBin/wiki/Configuration

[main]
discussion = false
opendiscussion = false
password = true
fileupload = false
burnafterreadingselected = true
shortlink = true
defaultformatter = "plaintext"
sizelimit = 2097152
templateselection = false
httpwarning = true
compression = "zlib"

[expire]
default = "1week"

[expire_options]
5min = 300
10min = 600
1hour = 3600
1day = 86400
1week = 604800

; RavenGuard rebuilds X-Forwarded-For, so the traffic limiter can trust it
[traffic]
limit = 10
header = "X_FORWARDED_FOR"

[purge]
limit = 300
batchsize = 10

[model]
class = Filesystem

[model_options]
; paste storage lives outside the web root, on the /data volume
dir = "/data"
