# syntax=docker/dockerfile:1.7
#
# Multi-stage build that produces a tiny image (~14MB) holding only the
# static binary, an example config, and a tarpit:tarpit nonroot user.
#
#   docker build -t tarpit-honeypot:latest .
#   docker run --rm \
#     -p 2222:2222 -p 8000:8000 -p 8088:8088 \
#     -v $PWD/var:/var/lib/tarpit-honeypot \
#     -v $PWD/configs/tarpit-honeypot.example.yaml:/etc/tarpit-honeypot/config.yaml:ro \
#     tarpit-honeypot:latest
#
# Privileged ports (53, 69, 102, 123, 161, 445, 502, ...) need either
# --user 0 OR a host capability grant; the systemd path is usually cleaner
# for production. For dev, remap to high ports in the config.

FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
RUN apk add --no-cache make git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN go build -trimpath \
      -ldflags "-s -w \
        -X github.com/rom/tarpit-honeypot/internal/version.Version=${VERSION} \
        -X github.com/rom/tarpit-honeypot/internal/version.Commit=${COMMIT} \
        -X github.com/rom/tarpit-honeypot/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/tarpit-honeypot ./cmd/tarpit-honeypot

# Final image: scratch + binary + a non-root user via a static passwd entry.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/tarpit-honeypot /usr/local/bin/tarpit-honeypot
COPY configs/tarpit-honeypot.example.yaml /etc/tarpit-honeypot/config.yaml

# Minimal passwd/group so the binary can drop privileges to uid 65532 (the
# "nonroot" convention from distroless). Operators can override via
# sensor.drop_user in the mounted config.
COPY --from=build /etc/passwd /etc/passwd
USER 65532:65532

VOLUME ["/var/lib/tarpit-honeypot"]
WORKDIR /var/lib/tarpit-honeypot
ENTRYPOINT ["/usr/local/bin/tarpit-honeypot"]
CMD ["run", "-c", "/etc/tarpit-honeypot/config.yaml"]
