#!/bin/bash

make build

sudo cp -f xray /usr/local/x-ui/bin/xray-linux-amd64
sudo cp -f monitor_config.json /usr/local/x-ui/bin/monitor_config.json

echo "x-ray has been successfully copied"