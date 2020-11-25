PLATFORM := linux
BUILD_DIR := build
GOBUILD = CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.zip
	rm -f *.dat

geoip.dat:
	wget -O geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat

geosite.dat:
	wget -O geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat

%.zip: % geosite.dat geoip.dat
	zip -du $(BUILD_DIR)/Xray-$@ -j $(BUILD_DIR)/Xray-$</*
	zip -du $(BUILD_DIR)/Xray-$@ -j *.dat
	rm -rf $(BUILD_DIR)/Xray-$<
	openssl dgst --md5 $(BUILD_DIR)/Xray-$@ | sed 's/([^)]*)//g' >> $(BUILD_DIR)/Xray-$@.dgst
	openssl dgst --sha1 $(BUILD_DIR)/Xray-$@ | sed 's/([^)]*)//g' >> $(BUILD_DIR)/Xray-$@.dgst
	openssl dgst --sha256 $(BUILD_DIR)/Xray-$@ | sed 's/([^)]*)//g' >> $(BUILD_DIR)/Xray-$@.dgst
	openssl dgst --sha512 $(BUILD_DIR)/Xray-$@ | sed 's/([^)]*)//g' >> $(BUILD_DIR)/Xray-$@.dgst

release: geosite.dat geoip.dat linux-32.zip linux-64.zip freebsd-32.zip freebsd-64.zip \
        openbsd-32.zip openbsd-64.zip dragonfly-64.zip linux-riscv64.zip linux-arm32-v5.zip \
        linux-arm32-v6.zip linux-arm32-v7a.zip linux-arm64-v8a.zip linux-mips32-hardfloat.zip \
        linux-mips32-softfloat.zip linux-mips32le-hardfloat.zip linux-mips32le-softfloat.zip \
        linux-mips64-hardfloat.zip linux-mips64-softfloat.zip linux-mips64le-hardfloat.zip \
        linux-mips64le-softfloat.zip linux-ppc64.zip linux-ppc64le.zip linux-s390x.zip \
        macos-64.zip windows-32.zip windows-64.zip windows-arm32-v7a.zip

linux-32:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=386 $(GOBUILD)/Xray-$@/xray ./main

linux-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=amd64 $(GOBUILD)/Xray-$@/xray ./main

freebsd-32:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=freebsd GOARCH=386 $(GOBUILD)/Xray-$@/xray ./main

freebsd-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=freebsd GOARCH=amd64 $(GOBUILD)/Xray-$@/xray ./main

openbsd-32:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=openbsd GOARCH=386 $(GOBUILD)/Xray-$@/xray ./main

openbsd-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=openbsd GOARCH=amd64 $(GOBUILD)/Xray-$@/xray ./main

dragonfly-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=dragonfly GOARCH=amd64 $(GOBUILD)/Xray-$@/xray ./main

linux-riscv64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=riscv64 $(GOBUILD)/Xray-$@/xray ./main

linux-arm32-v5:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=arm GOARM=5 $(GOBUILD)/Xray-$@/xray ./main

linux-arm32-v6:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=arm GOARM=6 $(GOBUILD)/Xray-$@/xray ./main

linux-arm32-v7a:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD)/Xray-$@/xray ./main

linux-arm64-v8a:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=arm64 $(GOBUILD)/Xray-$@/xray ./main

linux-mips32-hardfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips GOMIPS=hardfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips32-softfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips32le-hardfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mipsle GOMIPS=hardfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips32le-softfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips64-hardfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips64 GOMIPS64=hardfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips64-softfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips64 GOMIPS64=softfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips64le-hardfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips64le GOMIPS64=hardfloat $(GOBUILD)/Xray-$@/xray ./main

linux-mips64le-softfloat:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=mips64le GOMIPS64=softfloat $(GOBUILD)/Xray-$@/xray ./main

linux-ppc64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=ppc64 $(GOBUILD)/Xray-$@/xray ./main

linux-ppc64le:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=ppc64le $(GOBUILD)/Xray-$@/xray ./main

linux-s390x:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=linux GOARCH=s390x $(GOBUILD)/Xray-$@/xray ./main

macos-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=darwin GOARCH=amd64 $(GOBUILD)/Xray-$@/xray ./main

windows-32:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=windows GOARCH=386 $(GOBUILD)/Xray-$@/xray.exe ./main

windows-64:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=windows GOARCH=amd64 $(GOBUILD)/Xray-$@/xray.exe ./main

windows-arm32-v7a:
	mkdir -p $(BUILD_DIR)/Xray-$@
	env GOOS=windows GOARCH=arm GOARM=7 $(GOBUILD)/Xray-$@/xray.exe ./main