#! /bin/bash

echo "Building Begin: $(date '+%H:%M:%S')"

CGO_ENABLED=0 go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main

echo "Building End: $(date '+%H:%M:%S')"
