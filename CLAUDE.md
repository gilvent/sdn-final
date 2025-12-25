# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SDN lab workspace for NYCU WINLAB coursework implementing a two-Autonomous System BGP topology with ONOS controller, OVS switches, and FRR routers. The project uses Docker containers, WireGuard tunnels, and VXLAN for connectivity.

## Build Commands

### Full Deployment

```bash
make deploy    # Start ONOS, create network, configure IPs (runs: onos, setup, config)
make clean     # Remove all containers, OVS bridges, and veth pairs
make all       # clean + deploy
```

### Step-by-Step Deployment

```bash
make onos      # Start ONOS controller container
make setup     # Create Docker containers and OVS topology
make config    # Configure IP addresses and FRR/BGP
make status    # Show FRR BGP status on both routers
```

### vRouter ONOS Application

```bash
cd vrouter
mvn clean install -DskipTests
onos-app localhost install! target/vrouter-1.0-SNAPSHOT.oar
onos-netcfg localhost config.json
```

## Architecture

### Two-AS BGP Topology

**AS65350 (SDN Domain)** - Managed by ONOS vRouter app:
- Hosts: h1 (172.16.35.2), h2 (172.16.35.3)
- Switches: ovs1, ovs2 (OpenFlow 1.4)
- Border router: frr0 (192.168.63.1)
- Virtual gateway: 172.16.35.1 / 2a0b:4e07:c4:35::1

**AS65351 (Traditional Domain)** - Standard FRR routing:
- Host: h3 (172.17.35.2)
- Router: frr1 (192.168.63.2)

**Inter-AS Link**: frr0 ↔ frr1 via 192.168.63.0/24 (eBGP)

**Transit to AS65000**: VXLAN over WireGuard tunnel (ovs2 → ovs3)

### vRouter Application Structure

```
vrouter/
├── pom.xml                           # Maven build (nycu.winlab:vrouter)
├── config.json                       # ONOS network configuration
└── src/main/java/nycu/winlab/vrouter/
    ├── AppComponent.java             # Main component (@Activate/@Deactivate)
    ├── VRouterConfig.java            # Configuration class
    └── NeighborAdvertisement2.java   # NDP packet handling
```

**Key ONOS services used**: PacketService, FlowRuleService, HostService, RouteService, InterfaceService, NetworkConfigRegistry

**vRouter features**: Learning bridge, ProxyARP, ProxyNDP, L3 routing, FPM integration with FRR

### Setup Scripts

- `create.sh` - Creates Docker containers (h1, h2, h3, frr0, frr1, onos), OVS bridges, veth pairs, VXLAN tunnel
- `config.sh` - Assigns IP addresses, configures default routes, starts FRR daemons
- `cleanup.sh` - Removes all containers and network components
- `start_onos.sh` - Starts ONOS with required apps (fpm, hostprovider, openflow, route-service)
- `install_vrouter.sh` - Builds and installs vRouter app

### FRR Configuration

FRR configs are in `config/frr0/` and `config/frr1/`:
- `frr.conf` - BGP configuration with neighbor definitions
- `daemons` - Enables zebra (with FPM on port 2620) and bgpd

## Common Commands

### ONOS CLI (ssh -p 8101 onos@localhost, password: rocks)

```bash
apps -a -s           # List active apps
flows                # Show flow rules
hosts                # Show discovered hosts
routes               # Show routes from FPM
log:tail             # View logs
```

### Debugging

```bash
docker exec frr0 vtysh -c "show bgp summary"              # Check BGP status
docker exec frr0 vtysh -c "show ip route"                 # Check routes
ovs-ofctl dump-flows ovs1 -O OpenFlow14                   # Show OVS flows
docker logs onos                                           # ONOS logs
```

### Container Access

```bash
docker exec -it h1 sh                                      # Shell into host
docker exec -it frr0 vtysh                                 # FRR CLI
docker exec -it onos bash                                  # ONOS container
```

## Project Milestones

1. Intra-AS Communication (h1 ↔ h2)
2. Inter-AS Communication (h1/h2 ↔ h3)
3. BGP Peering with AS65000 (transit network)
4. Peer Network to Peer Network Communication (AS65340/AS65360)

## Key Files

- `vrouter/config.json` - vRouter app configuration (gateway IPs, FRR connect point)
- `config/frr0/frr.conf` - AS65350 BGP configuration
- `config/frr1/frr.conf` - AS65351 BGP configuration
- `STU-35.conf` - WireGuard tunnel configuration
- `fpm-config.json` - FPM (Forwarding Plane Manager) configuration
