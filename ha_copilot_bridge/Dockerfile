ARG BUILD_ARCH
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base:3.22

RUN apk add --no-cache python3 tailscale

COPY run.sh /run.sh
COPY app /app

RUN chmod 0755 /run.sh

CMD ["/run.sh"]
