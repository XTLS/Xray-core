FROM golang:1.24-alpine AS builder

LABEL org.opencontainers.image.source="https://github.com/XTLS/Xray-core" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.title="xray-core"

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid=" -v ./main

FROM alpine:3.22.0

COPY --from=builder /src/xray /usr/local/bin/xray
RUN  adduser -D -u 10001 xray &&\
     chmod +x /usr/local/bin/xray &&\
     mkdir -p /etc/xray /var/log/xray &&\
     echo {} > /etc/xray/config.json

WORKDIR /etc/xray
USER xray

ENTRYPOINT ["xray", "-c", "/etc/xray/config.json"]
