#!/bin/bash
set -e

# Script to prepare the network for a different network ID
# Usage: ./prepare_network_id.sh <new_network_id>
# Example: ./prepare_network_id.sh 34

if [ -z "$1" ]; then
    echo "Usage: $0 <new_network_id>"
    echo "Example: $0 34"
    exit 1
fi

NEW_ID="$1"
OLD_ID=35  # Default network ID

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Preparing network for ID: ${NEW_ID} (replacing ${OLD_ID})"

# --- 1. Update NETWORK_ID variable in create.sh and config.sh ---
echo "Updating NETWORK_ID variable in shell scripts..."
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${NEW_ID}/" "${SCRIPT_DIR}/create.sh"
sed -i "s/^NETWORK_ID=.*/NETWORK_ID=${NEW_ID}/" "${SCRIPT_DIR}/config.sh"

# --- 2. Update FRR configurations ---
echo "Updating FRR configurations..."

# frr0/frr.conf replacements
sed -i "s/172\.16\.${OLD_ID}/172.16.${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/172\.17\.${OLD_ID}/172.17.${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/192\.168\.70\.${OLD_ID}/192.168.70.${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/2a0b:4e07:c4:${OLD_ID}/2a0b:4e07:c4:${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/2a0b:4e07:c4:1${OLD_ID}/2a0b:4e07:c4:1${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/fd70::${OLD_ID}/fd70::${NEW_ID}/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
# ASN replacements: 65350 -> 653${NEW_ID}0, 65351 -> 653${NEW_ID}1
sed -i "s/653${OLD_ID}0/653${NEW_ID}0/g" "${SCRIPT_DIR}/config/frr0/frr.conf"
sed -i "s/653${OLD_ID}1/653${NEW_ID}1/g" "${SCRIPT_DIR}/config/frr0/frr.conf"

# frr1/frr.conf replacements
sed -i "s/172\.17\.${OLD_ID}/172.17.${NEW_ID}/g" "${SCRIPT_DIR}/config/frr1/frr.conf"
sed -i "s/2a0b:4e07:c4:1${OLD_ID}/2a0b:4e07:c4:1${NEW_ID}/g" "${SCRIPT_DIR}/config/frr1/frr.conf"
# ASN replacements
sed -i "s/653${OLD_ID}0/653${NEW_ID}0/g" "${SCRIPT_DIR}/config/frr1/frr.conf"
sed -i "s/653${OLD_ID}1/653${NEW_ID}1/g" "${SCRIPT_DIR}/config/frr1/frr.conf"

# --- 3. Update vrouter/config.json ---
echo "Updating vrouter/config.json..."
sed -i "s/172\.16\.${OLD_ID}/172.16.${NEW_ID}/g" "${SCRIPT_DIR}/vrouter/config.json"
sed -i "s/192\.168\.70\.${OLD_ID}/192.168.70.${NEW_ID}/g" "${SCRIPT_DIR}/vrouter/config.json"
sed -i "s/2a0b:4e07:c4:${OLD_ID}/2a0b:4e07:c4:${NEW_ID}/g" "${SCRIPT_DIR}/vrouter/config.json"
sed -i "s/fd70::${OLD_ID}/fd70::${NEW_ID}/g" "${SCRIPT_DIR}/vrouter/config.json"

# --- 4. Update OLD_ID for future runs ---
# This allows the script to be run multiple times with different IDs
sed -i "s/^OLD_ID=.*/OLD_ID=${NEW_ID}/" "${SCRIPT_DIR}/prepare_network_id.sh"

echo "Done! Network ID updated from ${OLD_ID} to ${NEW_ID}"
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
