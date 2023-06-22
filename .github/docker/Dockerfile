# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:alpine AS build
WORKDIR /src
COPY . .
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main

FROM --platform=${TARGETPLATFORM} alpine:latest
WORKDIR /root
COPY .github/docker/files/config.json /etc/xray/config.json
COPY --from=build /src/xray /usr/bin/xray
RUN set -ex \
	&& apk add --no-cache tzdata ca-certificates \
	&& mkdir -p /var/log/xray /usr/share/xray \
    && chmod +x /usr/bin/xray \
	&& wget -O /usr/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat \
	&& wget -O /usr/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

VOLUME /etc/xray
ENV TZ=Asia/Shanghai
ENTRYPOINT [ "/usr/bin/xray" ]
CMD [ "-config", "/etc/xray/config.json" ]
