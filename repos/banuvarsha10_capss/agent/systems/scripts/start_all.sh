#!/bin/bash

echo "Starting CAPSS Testbed..."

./start_core.sh

sleep 5

gnome-terminal -- bash -c "./start_gnb.sh"

sleep 3

gnome-terminal -- bash -c "./start_ue.sh"