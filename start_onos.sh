#!/bin/bash
set -e

# start_onos.sh - Start ONOS container with essential apps pre-activated

echo "Starting ONOS container with apps: $ONOS_APPS"
docker run --rm --name onos -d \
  -p 8181:8181 -p 6653:6653 -p 8101:8101 -p 2620:2620 \
  -e ONOS_APPS="drivers,fpm,gui2,hostprovider,lldpprovider,openflow,openflow-base,optical-model,route-service" \
  onosproject/onos:2.7-latest
