.PHONY: all onos setup config clean deploy bgp-summary bgp-table frr-routes bgp-adv-routes 

# Variables
FINAL_DIR := .
CREATE_SCRIPT := $(FINAL_DIR)/create.sh
CONFIG_SCRIPT := $(FINAL_DIR)/config.sh
CLEANUP_SCRIPT := $(FINAL_DIR)/cleanup.sh
START_ONOS_SCRIPT := $(FINAL_DIR)/start_onos.sh

all: clean deploy

deploy: onos setup config

onos:
	@echo "--- 🚀 Starting ONOS Controller ---"
	@bash $(START_ONOS_SCRIPT)

setup:
	@echo "--- 🛠️ Creating Network Components and Topology ---"
	@bash $(CREATE_SCRIPT)

config:
	@echo "--- ⚙️ Configuring IP Addresses and FRR/BGP ---"
	@bash $(CONFIG_SCRIPT)

clean:
	@echo "--- 🧹 Cleaning up Network Resources ---"
	@bash $(CLEANUP_SCRIPT)

bgp-summary:
	@echo "--- 📊 FRR BGP Status ---"
	@echo "\n=== frr0 (AS65350) ===" && docker exec frr0 vtysh -c "show bgp summary" || true
	@echo "\n=== frr1 (AS65351) ===" && docker exec frr1 vtysh -c "show bgp summary" || true

frr-routes:
	@echo "--- 📊 FRR Routing ---"
	@echo "\n=== frr0 (AS65350) ===" && docker exec frr0 vtysh -c "show ip route" || true
	@echo "\n=== frr1 (AS65351) ===" && docker exec frr1 vtysh -c "show ip route" || true

bgp-table:
	@echo "--- 📊 BGP Routing Table ---"
	@echo "\n=== frr0 (AS65350) ===" && docker exec frr0 vtysh -c "show bgp ipv4 unicast" || true
	@echo "\n=== frr1 (AS65351) ===" && docker exec frr1 vtysh -c "show bgp ipv4 unicast" || true

bgp-adv-routes:
	@echo "--- 📊 Advertised Routes ---"
	@echo "\n=== To AS65000 (IPv4) ===" && docker exec frr0 vtysh -c "show bgp ipv4 unicast neighbor 192.168.70.253 adv"
	@echo "\n=== To AS65000 (IPv6) ===" && docker exec frr0 vtysh -c "show bgp ipv6 unicast neighbor fd70::fe adv"
	

# Ensure the directory exists
$(FINAL_DIR):
	@mkdir -p $(FINAL_DIR)