#!/bin/bash
set -e

# Network ID (e.g., 35 for AS65350/AS65351)
NETWORK_ID=35

# --- 1. Helper function for Docker exec ---
dexec() {
    docker exec "$@"
}

# --- 2. AS65xx1 (172.17.${NETWORK_ID}.0/24) ---
echo "Configuring AS65xx1 (h3 and r1/frr1)..."
# h3 (172.17.${NETWORK_ID}.2/24) - Direct veth connection
# Interface name is eth0 (set by create.sh)
dexec h3 ip addr add 172.17.${NETWORK_ID}.2/24 dev eth0
# Set up a default route to r1 (172.17.${NETWORK_ID}.1)
dexec h3 ip route replace default via 172.17.${NETWORK_ID}.1

# r1 (frr1) Intra-AS IP (172.17.${NETWORK_ID}.1/24) - Direct veth connection
# Interface name is eth1 (set by create.sh)
dexec frr1 ip addr add 172.17.${NETWORK_ID}.1/24 dev eth1

# --- 3. AS65xx0 (172.16.${NETWORK_ID}.0/24 and 192.168.100.0/24) ---
echo "Configuring AS65xx0 (h1, h2, ctl, r0/frr0)..."

# Interfaces connected to ovs1 are typically eth0, and ovs2 is eth0 for h1
# NOTE: The connect_to_ovs function renames the interface inside the container to eth0

# h2 (172.16.${NETWORK_ID}.3/24)
dexec h2 ip addr add 172.16.${NETWORK_ID}.3/24 dev eth0
dexec h2 ip route replace default via 172.16.${NETWORK_ID}.69

# h1 (172.16.${NETWORK_ID}.2/24)
dexec h1 ip addr add 172.16.${NETWORK_ID}.2/24 dev eth0
dexec h1 ip route replace default via 172.16.${NETWORK_ID}.69

# ONOS BGP Peering Interface
echo "Configuring ONOS container for BGP peering..."
ONOS_PID=$(docker inspect -f '{{.State.Pid}}' onos)
if [ -z "$ONOS_PID" ]; then
  echo "Error: Could not find PID for 'onos' container. Is it running?" >&2
  exit 1
fi
nsenter -t $ONOS_PID -n ip addr add 192.168.100.2/24 dev eth1
nsenter -t $ONOS_PID -n ip -6 addr add fd63::3/64 dev eth1

# r0 (frr0) Multi-homed IP
R0_IF_OVS1=eth0 # Interface connected to ovs1
dexec frr0 ip addr add 192.168.63.1/24 dev ${R0_IF_OVS1}
dexec frr0 ip addr add 172.16.${NETWORK_ID}.69/24 dev ${R0_IF_OVS1}
dexec frr0 ip addr add 192.168.100.3/24 dev ${R0_IF_OVS1}
dexec frr0 ip addr add 192.168.70.${NETWORK_ID}/24 dev ${R0_IF_OVS1}  # For VXLAN to ovs3

# Set MAC address on frr0's eth0
# This MAC matches the MAC configured in the vrouter ONOS app
dexec frr0 ip link set ${R0_IF_OVS1} address 00:00:00:00:${NETWORK_ID}:01


# --- 4. Inter-AS Link (r1 <-> ovs1) ---
echo "Configuring Inter-AS link (r1/frr1 on AS65xx0 side)..."
# R1_IF_OVS1 is the interface connected to ovs1.
# connect_to_ovs ensures this is named 'eth0'.
R1_IF_OVS1=eth0

# r1 (frr1) Inter-AS IP (192.168.63.2/24)
dexec frr1 ip addr add 192.168.63.2/24 dev ${R1_IF_OVS1}


# BGP is pre-configured via mounted config files in config/frr0/ and config/frr1/
# Reload FRR config now that interfaces are ready (vtysh -b re-reads boot config)
echo "Reloading FRR configuration..."
docker exec frr0 vtysh -b
docker exec frr1 vtysh -b
sleep 2

echo "Configuration complete."
echo "You can check status with 'docker exec frr0 vtysh -c \"show bgp summary\"'"

# --- 5. IPv6 Configuration ---
echo "Configuring IPv6 addresses and routes..."

# h3 (2a0b:4e07:c4:1${NETWORK_ID}::2/64) -> GW: frr1 (2a0b:4e07:c4:1${NETWORK_ID}::1)
dexec h3 ip -6 addr add 2a0b:4e07:c4:1${NETWORK_ID}::2/64 dev eth0
dexec h3 ip -6 route replace default via 2a0b:4e07:c4:1${NETWORK_ID}::1

# frr1 (2a0b:4e07:c4:1${NETWORK_ID}::1/64, fd63::2/64)
# eth1 faces h3, eth0 faces ovs1(frr0)
dexec frr1 ip -6 addr add 2a0b:4e07:c4:1${NETWORK_ID}::1/64 dev eth1
dexec frr1 ip -6 addr add fd63::2/64 dev eth0

# h2 (2a0b:4e07:c4:${NETWORK_ID}::3/64) -> GW: vrouter (2a0b:4e07:c4:${NETWORK_ID}::69)
dexec h2 ip -6 addr add 2a0b:4e07:c4:${NETWORK_ID}::3/64 dev eth0
dexec h2 ip -6 route replace default via 2a0b:4e07:c4:${NETWORK_ID}::69

# h1 (2a0b:4e07:c4:${NETWORK_ID}::2/64) -> GW: vrouter (2a0b:4e07:c4:${NETWORK_ID}::69)
dexec h1 ip -6 addr add 2a0b:4e07:c4:${NETWORK_ID}::2/64 dev eth0
dexec h1 ip -6 route replace default via 2a0b:4e07:c4:${NETWORK_ID}::69

# frr0 (fd63::1/64, fd70::${NETWORK_ID}/64, 2a0b:4e07:c4:${NETWORK_ID}::69/64)
# All on eth0 (connected to ovs1)
dexec frr0 ip -6 addr add fd63::1/64 dev eth0
dexec frr0 ip -6 addr add fd70::${NETWORK_ID}/64 dev eth0
dexec frr0 ip -6 addr add 2a0b:4e07:c4:${NETWORK_ID}::69/64 dev eth0