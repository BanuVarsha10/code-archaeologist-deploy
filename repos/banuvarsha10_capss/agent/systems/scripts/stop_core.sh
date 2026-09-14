#!/bin/bash

echo "Stopping Open5GS Core..."

SERVICES=(
open5gs-bsfd
open5gs-pcfd
open5gs-nssfd
open5gs-upfd
open5gs-smfd
open5gs-udrd
open5gs-udmd
open5gs-ausfd
open5gs-amfd
open5gs-scpd
open5gs-nrfd
)

for service in "${SERVICES[@]}"
do
    sudo systemctl stop $service
done

echo "Stopped."