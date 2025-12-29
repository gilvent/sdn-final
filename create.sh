#!/bin/bash
set -e

# Network ID (e.g., 35 for AS65350/AS65351)
# This is used for VXLAN tunnel IPs: 192.168.6X.NETWORK_ID
NETWORK_ID=35
PEER1_NETWORK_ID=34
PEER2_NETWORK_ID=36

# --- 1. Cleanup previous run ---
# ./cleanup.sh > /dev/null 2>&1 || true


# --- 2. Create Docker Containers ---
echo "Creating containers (h1, h2, h3, frr0, frr1)..."
docker run -d --name h1 --hostname h1 --network none --cap-add=NET_ADMIN host sleep infinity
docker run -d --name h2 --hostname h2 --network none --cap-add=NET_ADMIN host sleep infinity
docker run -d --name h3 --hostname h3 --network none --cap-add=NET_ADMIN host sleep infinity

# FRR containers for routers r0 and r1
# Mount config files from config/ directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run -d --name frr0 --hostname r0 \
  --network none \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --privileged \
  -v "${SCRIPT_DIR}/config/frr0/frr.conf:/etc/frr/frr.conf:ro" \
  -v "${SCRIPT_DIR}/config/frr0/daemons:/etc/frr/daemons:ro" \
  frrouting/frr-debian

docker run -d --name frr1 --hostname r1 \
  --network none \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --privileged \
  -v "${SCRIPT_DIR}/config/frr1/frr.conf:/etc/frr/frr.conf:ro" \
  -v "${SCRIPT_DIR}/config/frr1/daemons:/etc/frr/daemons:ro" \
  frrouting/frr-debian

# ONOS Controller is started separately via start_onos.sh (run 'make onos' first)

echo "Creating OVS bridges ovs1 and ovs2..."
ovs-vsctl add-br ovs1 -- set bridge ovs1 protocols=OpenFlow14 -- set bridge ovs1 other-config:datapath-id=0000000000000001

# Use localhost (Host -> Container Port Mapping) to avoid In-Band Deadlock
ovs-vsctl set-controller ovs1 tcp:127.0.0.1:6653

# Assign IP to ovs1 bridge itself (optional, good for debug)
ip addr add 192.168.100.1/24 dev ovs1 || echo "IP 192.168.100.1 already assigned or failed"
ip link set ovs1 up

ovs-vsctl add-br ovs2 -- set bridge ovs2 protocols=OpenFlow14 -- set bridge ovs2 other-config:datapath-id=0000000000000002
ovs-vsctl set-controller ovs2 tcp:127.0.0.1:6653

# NOTE: Removed NORMAL flows - vrouter app now handles all L2 switching
# ovs-ofctl add-flow ovs1 "priority=6,actions=NORMAL" -O OpenFlow14
# ovs-ofctl add-flow ovs2 "priority=6,actions=NORMAL" -O OpenFlow14

# Enable IP forwarding in FRR containers
echo "Enabling IP forwarding in FRR containers..."
docker exec frr0 sysctl -w net.ipv4.ip_forward=1 > /dev/null
docker exec frr1 sysctl -w net.ipv4.ip_forward=1 > /dev/null
docker exec frr0 sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
docker exec frr1 sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null


# --- 4. Connect Components to OVS Bridges (AS65350) ---
echo "Connecting AS65350 components to OVS bridges..."

# Helper function to connect a Docker container to an OVS bridge
connect_to_ovs() {
    local host_name=$1
    local ovs_name=$2
    local veth_host=${host_name}-veth
    local veth_ovs=${host_name}-port

    # Create veth pair
    ip link add ${veth_host} type veth peer name ${veth_ovs}

    # Move one end into the container
    local pid=$(docker inspect -f '{{.State.Pid}}' ${host_name})
    ip link set ${veth_host} netns $pid

    # Add the other end to the OVS bridge
    ovs-vsctl add-port ${ovs_name} ${veth_ovs}
    ip link set ${veth_ovs} up

    # Rename the interface inside the container to eth0 and bring it up
    nsenter -t $pid -n ip link set dev ${veth_host} name eth0
    nsenter -t $pid -n ip link set eth0 up
}

# h2 <-> ovs1
connect_to_ovs h2 ovs1

# h1 <-> ovs2
connect_to_ovs h1 ovs2

# frr0 (r0) <-> ovs1 (interface 1)
connect_to_ovs frr0 ovs1

# --- 4.1 Connect ONOS to ovs1 for BGP Peering ---
echo "Connecting ONOS container to ovs1 for BGP peering..."
ONOS_PID=$(docker inspect -f '{{.State.Pid}}' onos)
if [ -z "$ONOS_PID" ]; then
  echo "Error: Could not find PID for 'onos' container. Is it running?"
  exit 1
fi
ip link add onos-veth type veth peer name onos-port
ip link set onos-veth netns $ONOS_PID
ovs-vsctl add-port ovs1 onos-port
ip link set onos-port up
# Use eth1 to avoid conflict with existing interface in ONOS container
nsenter -t $ONOS_PID -n ip link set dev onos-veth name eth1
nsenter -t $ONOS_PID -n ip link set eth1 up

# --- 5. Connect ovs1 <-> ovs2 ---
echo "Connecting ovs1 to ovs2..."
ip link add ovs1-ovs2-veth type veth peer name ovs2-ovs1-veth
ovs-vsctl add-port ovs1 ovs1-ovs2-veth
ovs-vsctl add-port ovs2 ovs2-ovs1-veth
ip link set ovs1-ovs2-veth up
ip link set ovs2-ovs1-veth up

# --- 5.1 VXLAN tunnel from ovs2 to ovs3 (via WireGuard) ---
echo "Creating VXLAN tunnel to ovs3..."
# local_ip: WireGuard interface IP (192.168.61.${NETWORK_ID})
# remote_ip: ovs3's IP on the WireGuard network (192.168.60.${NETWORK_ID})
ovs-vsctl add-port ovs2 TO_TA_VXLAN -- set interface TO_TA_VXLAN type=vxlan \
    options:remote_ip=192.168.60.${NETWORK_ID} \
    options:local_ip=192.168.61.${NETWORK_ID}

ovs-vsctl add-port ovs2 TO_${PEER1_NETWORK_ID}_VXLAN -- set interface TO_${PEER1_NETWORK_ID}_VXLAN type=vxlan \
    options:remote_ip=192.168.61.${PEER1_NETWORK_ID} \
    options:local_ip=192.168.61.${NETWORK_ID}

ovs-vsctl add-port ovs2 TO_${PEER2_NETWORK_ID}_VXLAN -- set interface TO_${PEER2_NETWORK_ID}_VXLAN type=vxlan \
    options:remote_ip=192.168.61.${PEER2_NETWORK_ID} \
    options:local_ip=192.168.61.${NETWORK_ID}



# --- 6. Intra AS65351 Connection (r1 <-> h3) ---
# This is a direct Docker link to simulate a simple link without OVS intermediary
echo "Connecting r1 (frr1) to h3..."
# echo "Connecting r1 (frr1) to h3..."
# Direct veth pair between h3 and frr1
# h3 side: eth0 (renaming existing docker eth0 to eth-mgmt)
# frr1 side: eth1 (leaving eth0 for connect_to_ovs to handle later)

ip link add h3-r1-veth type veth peer name r1-h3-veth

# Configure h3 side
H3_PID=$(docker inspect -f '{{.State.Pid}}' h3)
# Rename existing eth0 if present
if nsenter -t $H3_PID -n ip link show eth0 > /dev/null 2>&1; then
    nsenter -t $H3_PID -n ip link set dev eth0 name eth-mgmt
fi
ip link set h3-r1-veth netns $H3_PID
nsenter -t $H3_PID -n ip link set dev h3-r1-veth name eth0
nsenter -t $H3_PID -n ip link set eth0 up

# Configure frr1 side
FRR1_PID=$(docker inspect -f '{{.State.Pid}}' frr1)
# We don't touch eth0 here, connect_to_ovs will handle it later. We use eth1.
ip link set r1-h3-veth netns $FRR1_PID
nsenter -t $FRR1_PID -n ip link set dev r1-h3-veth name eth1
nsenter -t $FRR1_PID -n ip link set eth1 up

# --- 7. Inter AS Connection (r1 <-> ovs1) ---
echo "Connecting r1 (frr1) to ovs1..."
# frr1 (r1) is a boundary router, it needs a connection to ovs1 (AS65350)
connect_to_ovs frr1 ovs1

echo "Setup complete. Run 'make config' to configure IPs."