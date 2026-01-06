#!/bin/bash
set -e

# Script to prepare the network for a specific network ID using templates
# Usage: ./setup_network_id.sh <main_id> <peer1_id> <peer2_id>
# Example: ./setup_network_id.sh 35 34 36

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <main_id> <peer1_id> <peer2_id>"
    echo "Example: $0 35 34 36"
    echo ""
    echo "  main_id  - Your network ID (xx)"
    echo "  peer1_id - First peer network ID (yy)"
    echo "  peer2_id - Second peer network ID (zz)"
    exit 1
fi

MAIN_ID="$1"
PEER1_ID="$2"
PEER2_ID="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${SCRIPT_DIR}/config-templates"

echo "Generating configuration files..."
echo "  Main network ID (xx): ${MAIN_ID}"
echo "  Peer 1 ID (yy): ${PEER1_ID}"
echo "  Peer 2 ID (zz): ${PEER2_ID}"
echo ""

# Helper function to replace placeholders in a template
# Replaces: xx -> MAIN_ID, yy -> PEER1_ID, zz -> PEER2_ID
generate_from_template() {
    local template="$1"
    local output="$2"

    sed -e "s/xx/${MAIN_ID}/g" \
        -e "s/yy/${PEER1_ID}/g" \
        -e "s/zz/${PEER2_ID}/g" \
        "$template" > "$output"

    echo "  Generated: $output"
}

# --- 1. Generate FRR configurations from templates ---
echo "Generating FRR configurations..."
generate_from_template "${TEMPLATE_DIR}/frr0.conf" "${SCRIPT_DIR}/config/frr0/frr.conf"
generate_from_template "${TEMPLATE_DIR}/frr1.conf" "${SCRIPT_DIR}/config/frr1/frr.conf"

# --- 2. Generate vrouter/config.json from template ---
echo "Generating vrouter/config.json..."
generate_from_template "${TEMPLATE_DIR}/vrouter-config.json" "${SCRIPT_DIR}/vrouter/config.json"

# --- 3. Update NETWORK_ID variables in shell scripts ---
echo "Updating shell scripts..."
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${MAIN_ID}/" "${SCRIPT_DIR}/create.sh"
sed -i "s/^PEER1_NETWORK_ID=.*/PEER1_NETWORK_ID=${PEER1_ID}/" "${SCRIPT_DIR}/create.sh"
sed -i "s/^PEER2_NETWORK_ID=.*/PEER2_NETWORK_ID=${PEER2_ID}/" "${SCRIPT_DIR}/create.sh"
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${MAIN_ID}/" "${SCRIPT_DIR}/config.sh"
echo "  Updated: create.sh"
echo "  Updated: config.sh"

echo ""
echo "Done! Configuration generated for network ${MAIN_ID} with peers ${PEER1_ID} and ${PEER2_ID}."
echo ""
echo "Files modified:"
echo "  - config/frr0/frr.conf (from template)"
echo "  - config/frr1/frr.conf (from template)"
echo "  - vrouter/config.json (from template)"
echo "  - create.sh (NETWORK_ID variables)"
echo "  - config.sh (NETWORK_ID variable)"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git diff"
echo "  2. Deploy the network: make deploy"
echo ""
echo "NEED MANUAL CONFIGURATION!"
echo "  1. vrouter/config.json: Use your WAN connect points (from ONOS GUI)"
echo "  2. vrouter/config.json: Use your frr0 IPv6 link-local address in ingress filters (`docker exec frr0 ip -6 addr show`)"
echo "  3. vrouter/config.json: Peer frr0 IPv6 link-local addresses (`sudo make frr0-routes`)"
echo "  4. AppComponent.java: Static IP-to-ConnectPoint mapping in `buildPeerIpToConnectPointMap()` method"
echo "35 WAN Connect Point: of:0000ceaa83f3a445/3"
echo "36 WAN Connect Point: of:000092a540f52b43/3"