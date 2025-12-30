#!/bin/bash
set -e

# Script to prepare the network for a different network ID
# Usage: ./prepare_network_id.sh <new_network_id>
# Example: ./prepare_network_id.sh 34
#
# This script SWAPS the network IDs. If you're network 35 and switch to 34,
# peer references to 34 will become 35 (your old ID becomes the peer).

if [ -z "$1" ]; then
    echo "Usage: $0 <new_network_id>"
    echo "Example: $0 34"
    exit 1
fi

NEW_ID="$1"
OLD_ID=34

if [ "$NEW_ID" = "$OLD_ID" ]; then
    echo "New ID ($NEW_ID) is the same as current ID ($OLD_ID). Nothing to do."
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Swapping network IDs: ${OLD_ID} <-> ${NEW_ID}"

# Helper function to swap IDs in a file using a temporary placeholder
# Usage: swap_ids <file> <pattern_prefix> <pattern_suffix>
swap_in_file() {
    local file="$1"
    local prefix="$2"
    local suffix="$3"

    # 3-step swap: OLD -> TEMP, NEW -> OLD, TEMP -> NEW
    sed -i "s/${prefix}${OLD_ID}${suffix}/${prefix}__TEMP_ID__${suffix}/g" "$file"
    sed -i "s/${prefix}${NEW_ID}${suffix}/${prefix}${OLD_ID}${suffix}/g" "$file"
    sed -i "s/${prefix}__TEMP_ID__${suffix}/${prefix}${NEW_ID}${suffix}/g" "$file"
}

# --- 1. Update NETWORK_ID variable in create.sh and config.sh ---
echo "Updating NETWORK_ID variable in shell scripts..."
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${NEW_ID}/" "${SCRIPT_DIR}/create.sh"
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${NEW_ID}/" "${SCRIPT_DIR}/config.sh"

# --- 2. Update FRR configurations (with swap) ---
echo "Updating FRR configurations..."

for frr_conf in "${SCRIPT_DIR}/config/frr0/frr.conf" "${SCRIPT_DIR}/config/frr1/frr.conf"; do
    # IPv4 network prefixes: 172.16.XX, 172.17.XX
    swap_in_file "$frr_conf" "172\.16\." ""
    swap_in_file "$frr_conf" "172\.17\." ""

    # BGP peering IP: 192.168.70.XX
    swap_in_file "$frr_conf" "192\.168\.70\." ""

    # IPv6 prefixes: 2a0b:4e07:c4:XX, 2a0b:4e07:c4:1XX
    swap_in_file "$frr_conf" "2a0b:4e07:c4:" ""
    swap_in_file "$frr_conf" "2a0b:4e07:c4:1" ""

    # IPv6 fd70::XX
    swap_in_file "$frr_conf" "fd70::" ""

    # ASN: 653XX0, 653XX1
    swap_in_file "$frr_conf" "653" "0"
    swap_in_file "$frr_conf" "653" "1"
done

# --- 3. Update vrouter/config.json (with swap) ---
echo "Updating vrouter/config.json..."
vrouter_conf="${SCRIPT_DIR}/vrouter/config.json"

swap_in_file "$vrouter_conf" "172\.16\." ""
swap_in_file "$vrouter_conf" "192\.168\.70\." ""
swap_in_file "$vrouter_conf" "2a0b:4e07:c4:" ""
swap_in_file "$vrouter_conf" "fd70::" ""

# MAC addresses: 00:00:00:00:XX:01, 00:00:00:00:XX:02
swap_in_file "$vrouter_conf" "00:00:00:00:" ":01"
swap_in_file "$vrouter_conf" "00:00:00:00:" ":02"

# Solicited-node multicast: ff02::1:ff00:XX
swap_in_file "$vrouter_conf" "ff02::1:ff00:" ""

# --- 4. Update OLD_ID for future runs ---
sed -i "s/^OLD_ID=.*/OLD_ID=${NEW_ID}/" "${SCRIPT_DIR}/prepare_network_id.sh"

echo "Done! Network IDs swapped: ${OLD_ID} <-> ${NEW_ID}"
echo ""
echo "Files modified:"
echo "  - create.sh (NETWORK_ID variable)"
echo "  - config.sh (NETWORK_ID variable)"
echo "  - config/frr0/frr.conf"
echo "  - config/frr1/frr.conf"
echo "  - vrouter/config.json"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git diff"
echo "  2. Deploy the network: make deploy"
