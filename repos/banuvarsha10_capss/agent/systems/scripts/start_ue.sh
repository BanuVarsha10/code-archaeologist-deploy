#!/bin/bash

echo "Starting UERANSIM UE..."

sudo pkill -f nr-ue 2>/dev/null

sleep 1

exec ~/5g-project/UERANSIM/build/nr-ue \
    -c ~/5g-project/UERANSIM/config/open5gs-ue.yaml