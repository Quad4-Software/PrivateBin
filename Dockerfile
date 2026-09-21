# syntax=docker/dockerfile:1

# Stage 1: build the RavenGuard WAF from pinned upstream source (0BSD).
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS ravenguard-build

ARG RG_COMMIT=f6d2aac90f0db1bd84ce8b4f0e33e2e73d13221d
ARG RG_VERSION=nightly-20260920-f6d2aac9
ADD --checksum=sha256:d2a3d5ea26c83e8ab5d8edc54e8395b4403a394a109e84c6cb20007b61802b69 \
	https://github.com/Quad4-Software/ravenguard/archive/${RG_COMMIT}.tar.gz /tmp/ravenguard.tar.gz

WORKDIR /src
RUN tar -xzf /tmp/ravenguard.tar.gz --strip-components=1 \
	&& CGO_ENABLED=0 GOOS=linux go build -trimpath \
		-ldflags="-s -w -X github.com/Quad4-Software/ravenguard/internal/version.Commit=${RG_COMMIT} -X github.com/Quad4-Software/ravenguard/internal/version.Version=${RG_VERSION}" \
		-o /out/ravenguard ./cmd/ravenguard

# Stage 2: runtime. RavenGuard listens on :8080 and proxies to nginx on
# 127.0.0.1:8000, which serves static assets and passes PHP to php-fpm on
# 127.0.0.1:9000.
FROM php:8.4-fpm-alpine@sha256:c68b19eac3042f36ed7dc7b1240712ad83d421f59e79c73357a645b520f7f68d

RUN apk add --no-cache nginx tini freetype libjpeg-turbo libpng \
	&& apk add --no-cache --virtual .gd-build freetype-dev libjpeg-turbo-dev libpng-dev \
	&& docker-php-ext-configure gd --with-freetype --with-jpeg \
	&& docker-php-ext-install -j"$(nproc)" gd opcache \
	&& apk del .gd-build \
	&& rm -f /usr/local/etc/php-fpm.d/*.conf \
	&& adduser -D -H -u 10001 privatebin \
	&& mkdir -p /data /var/lib/nginx/logs \
	&& chown -R 10001:10001 /data /var/lib/nginx /var/log/nginx \
	&& ln -sf /dev/stderr /var/lib/nginx/logs/error.log \
	&& ln -sf /dev/stdout /var/lib/nginx/logs/access.log

WORKDIR /srv/privatebin
COPY index.php manifest.json robots.txt browserconfig.xml /srv/privatebin/
COPY cfg /srv/privatebin/cfg
COPY css /srv/privatebin/css
COPY i18n /srv/privatebin/i18n
COPY img /srv/privatebin/img
COPY js /srv/privatebin/js
COPY lib /srv/privatebin/lib
COPY tpl /srv/privatebin/tpl
COPY vendor /srv/privatebin/vendor
COPY docker/conf.php /srv/privatebin/cfg/conf.php
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-privatebin.ini
COPY docker/ravenguard.toml /etc/ravenguard/ravenguard.toml
COPY docker/seccomp-ravenguard.json /etc/ravenguard/seccomp.json
COPY docker/entrypoint.sh /entrypoint.sh
COPY --from=ravenguard-build --chmod=755 /out/ravenguard /usr/local/bin/ravenguard

# generate subresource integrity hashes for every served css and js file,
# the template reads them from the sri config section
RUN php -r ' \
	$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("/srv/privatebin", FilesystemIterator::SKIP_DOTS)); \
	$sri = "\n[sri]\n"; \
	foreach ($it as $f) { \
		$rel = substr($f->getPathname(), 16); \
		if (preg_match("#^(css|js)/.*\\.(css|js)$#", $rel)) { \
			$sri .= $rel . " = \"sha512-" . base64_encode(hash_file("sha512", $f->getPathname(), true)) . "\"\n"; \
		} \
	} \
	file_put_contents("/srv/privatebin/cfg/conf.php", $sri, FILE_APPEND); \
	' && chmod 755 /entrypoint.sh && chown -R 10001:10001 /srv/privatebin

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="PrivateBin" \
	org.opencontainers.image.description="Zero-knowledge encrypted pastebin behind the RavenGuard WAF" \
	org.opencontainers.image.url="https://github.com/Quad4-Software/VoidBin" \
	org.opencontainers.image.source="https://github.com/Quad4-Software/VoidBin" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.licenses="zlib-acknowledgement" \
	org.opencontainers.image.vendor="Quad4 Software"

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
	CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
ENTRYPOINT ["/sbin/tini", "-g", "--", "/entrypoint.sh"]
