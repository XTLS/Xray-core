FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/xray ./main
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/rest-test-server ./proxy/vless/validator/rest/test_serv

FROM debian:bookworm-slim

COPY --from=build /out/xray /usr/local/bin/xray
COPY --from=build /out/rest-test-server /usr/local/bin/rest-test-server

ENTRYPOINT ["/usr/local/bin/rest-test-server"]
