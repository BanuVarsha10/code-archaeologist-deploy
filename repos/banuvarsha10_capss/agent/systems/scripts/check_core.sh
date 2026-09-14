#!/bin/bash

echo "======================================"
echo "       Open5GS Core Status"
echo "======================================"

services=(
    open5gs-nrfd
    open5gs-amfd
    open5gs-smfd
    open5gs-upfd
    open5gs-ausfd
    open5gs-udmd
    open5gs-udrd
    open5gs-pcfd
    open5gs-nssfd
)

for service in "${services[@]}"
do
    if systemctl is-active --quiet "$service"; then
        echo "[OK]   $service"
    else
        echo "[FAIL] $service"
    fi
done

