FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl bash

COPY deploy/demo/entrypoint.sh /entrypoint.sh
COPY deploy/init.sh /usr/local/bin/pki-init
COPY deploy/pki-backup.sh /usr/local/bin/pki-backup
COPY pki /usr/local/bin/pki

RUN chmod +x /entrypoint.sh /usr/local/bin/pki && \
    mkdir -p /etc/pki /var/lib/pki /certs

EXPOSE 4430

ENTRYPOINT ["/entrypoint.sh"]
