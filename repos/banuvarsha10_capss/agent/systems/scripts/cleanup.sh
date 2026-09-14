#!/bin/bash

echo "Cleaning CAPSS Environment..."

sudo pkill -f nr-ue
sudo pkill -f nr-gnb

sleep 2

sudo ip link delete uesimtun0 2>/dev/null || true

echo "Cleanup completed."