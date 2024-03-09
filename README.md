# VpnServer



Xray-core: https://github.com/XTLS/Xray-core



### Spike protocol:

https://github.com/xinruleng/bisheng-vpn2/blob/main/doc/Spike_Protocol.md



### Build:

```shell
go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main
```



### Server run:

```shell
./xray run -c config_server.json
```

### Client run:

```shell
./xray run -c config_client.json
```
