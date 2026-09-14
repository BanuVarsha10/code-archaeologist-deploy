#!/bin/bash

echo "Starting UERANSIM gNB..."

sudo pkill -f nr-gnb 2>/dev/null

sleep 1

exec ~/5g-project/UERANSIM/build/nr-gnb \
    -c ~/5g-project/UERANSIM/config/open5gs-gnb.yaml