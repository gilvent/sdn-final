.PHONY: all onos setup config clean deploy \
		bgp-summary frr0-routes frr1-routes \
		frr0-bgp-table frr1-bgp-table \
		frr0-adv-routes frr1-adv-routes \
		frr0-rec-routes frr1-rec-routes

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

frr0-routes:
	@echo "--- 📊 FRR Routing frr0 (AS65350) ---"
	@echo "\n=== IPv4 ===" && docker exec frr0 vtysh -c "show ip route" || true
	@echo "\n=== IPv6 ===" && docker exec frr0 vtysh -c "show ipv6 route" || true

frr1-routes:
	@echo "--- 📊 FRR Routing frr1 (AS65351) ---"
	@echo "\n=== IPv4 ===" && docker exec frr1 vtysh -c "show ip route" || true
	@echo "\n=== IPv6 ===" && docker exec frr1 vtysh -c "show ipv6 route" || true

frr0-bgp-table:
	@echo "--- 📊 BGP Routing Table (AS65350) ---"
	@echo "\n=== IPv4 ===" && docker exec frr0 vtysh -c "show bgp ipv4 unicast" || true
	@echo "\n=== IPv6 ===" && docker exec frr0 vtysh -c "show bgp ipv6 unicast" || true

frr1-bgp-table:
	@echo "--- 📊 BGP Routing Table (AS65351) ---"
	@echo "\n=== IPv4 ===" && docker exec frr1 vtysh -c "show bgp ipv4 unicast" || true
	@echo "\n=== IPv6 ===" && docker exec frr1 vtysh -c "show bgp ipv6 unicast" || true

frr0-adv-routes:
	@echo "--- 📊 Advertised Routes (AS65350) ---"
	@echo "\n=== To AS65000 (IPv4) ===" && docker exec frr0 vtysh -c "show bgp ipv4 nei 192.168.70.253 adv"
	@echo "\n=== To AS65000 (IPv6) ===" && docker exec frr0 vtysh -c "show bgp ipv6 nei fd70::fe adv"
	@echo "\n=== To frr1 (IPv4) ===" && docker exec frr0 vtysh -c "show bgp ipv4 nei 192.168.63.2 adv
	@echo "\n=== To frr1 (IPv6) ===" && docker exec frr0 vtysh -c "show bgp ipv6 nei fd63::2 adv"

frr1-adv-routes:
	@echo "--- 📊 Advertised Routes (AS65351) ---"
	@echo "\n=== To frr0 (IPv4) ===" && docker exec frr1 vtysh -c "show bgp ipv4 nei 192.168.63.1 adv"
	@echo "\n=== To frr0 (IPv6) ===" && docker exec frr1 vtysh -c "show bgp ipv6 nei fd63::1 adv"

frr0-rec-routes:
	@echo "--- 📊 Received Routes (AS65350) ---"
	@echo "\n=== From AS65000 (IPv4) ===" && docker exec frr0 vtysh -c "show ip bgp nei 192.168.70.253 routes"
	@echo "\n=== From AS65000 (IPv6) ===" && docker exec frr0 vtysh -c "show bgp ipv6 nei fd70::fe routes"
	@echo "\n=== From frr1 (IPv4) ===" && docker exec frr0 vtysh -c "show ip bgp nei 192.168.63.2 routes"
	@echo "\n=== From frr1 (IPv6) ===" && docker exec frr0 vtysh -c "show bgp ipv6 nei fd63::2 routes"

frr1-rec-routes:
	@echo "--- 📊 Received Routes (AS65351) ---"
	@echo "\n=== From frr0 (IPv4) ===" && docker exec frr1 vtysh -c "show ip bgp nei 192.168.63.1 routes"
	@echo "\n=== From frr0 (IPv6) ===" && docker exec frr1 vtysh -c "show bgp ipv6 nei fd63::1 routes"

# Ensure the directory exists
$(FINAL_DIR):
	@mkdir -p $(FINAL_DIR)