module github.com/xtls/xray-core/api-client

go 1.25

require (
	github.com/xtls/xray-core v0.0.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20200812162917-85c65e2d0165 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/quic-go/quic-go v0.56.0 // indirect
	github.com/refraction-networking/utls v1.8.1 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/sing v0.5.1 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20240715131351-a2f2c23f1771 // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/xtls/reality v0.0.0-20251014195629-e4eec4520535 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

replace github.com/xtls/xray-core => ../

// 使用 generated 目录下的 gRPC 客户端代码
replace github.com/xtls/xray-core/app/stats/command => ./generated/app/stats/command

replace github.com/xtls/xray-core/app/proxyman/command => ./generated/app/proxyman/command
