#!/bin/bash
set -e

echo "Stopping and removing all containers..."
docker stop h1 h2 h3 frr0 frr1 onos > /dev/null 2>&1 || true
docker rm h1 h2 h3 frr0 frr1 onos > /dev/null 2>&1 || true

echo "Removing Docker networks..."
docker network rm as65351-intra > /dev/null 2>&1 || true

echo "Removing OVS bridges and associated veth ports..."
# Remove veth pairs attached to OVS bridges first
ovs-vsctl del-port ovs1 h2-port > /dev/null 2>&1 || true
ovs-vsctl del-port ovs1 onos-port > /dev/null 2>&1 || true
ovs-vsctl del-port ovs1 frr0-port > /dev/null 2>&1 || true
ovs-vsctl del-port ovs1 frr1-port > /dev/null 2>&1 || true
ovs-vsctl del-port ovs1 ovs1-ovs2-veth > /dev/null 2>&1 || true

ovs-vsctl del-port ovs2 h1-port > /dev/null 2>&1 || true
ovs-vsctl del-port ovs2 ovs2-ovs1-veth > /dev/null 2>&1 || true
ovs-vsctl del-port ovs2 TO_TA_VXLAN > /dev/null 2>&1 || true

# Delete OVS bridges
ovs-vsctl del-br ovs1 > /dev/null 2>&1 || true
ovs-vsctl del-br ovs2 > /dev/null 2>&1 || true

# Remove any remaining veth pairs that might not have been cleaned up automatically
ip link delete ovs1-ovs2-veth type veth > /dev/null 2>&1 || true
ip link delete h2-veth type veth > /dev/null 2>&1 || true
ip link delete h2-port type veth > /dev/null 2>&1 || true
ip link delete h1-veth type veth > /dev/null 2>&1 || true
ip link delete h1-port type veth > /dev/null 2>&1 || true
ip link delete onos-veth type veth > /dev/null 2>&1 || true
ip link delete onos-port type veth > /dev/null 2>&1 || true
ip link delete frr0-veth type veth > /dev/null 2>&1 || true
ip link delete frr0-port type veth > /dev/null 2>&1 || true
ip link delete frr1-veth type veth > /dev/null 2>&1 || true
ip link delete frr1-port type veth > /dev/null 2>&1 || true
ip link delete h3-r1-veth type veth > /dev/null 2>&1 || true
ip link delete r1-h3-veth type veth > /dev/null 2>&1 || true

echo "Cleanup complete."