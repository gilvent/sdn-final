# Implementation Plan: Source-Based Anycast Server Response

## Overview

This plan implements anycast routing where the server closest to the traffic source responds to requests. Two `traefik/whoami` containers will share the same IP address (172.16.35.100), with routing decisions based on packet ingress point.

## Topology Summary

```
                    ┌──────────────┐
                    │   AS65000    │
                    │   (ovs3)     │
                    └──────┬───────┘
                           │ VXLAN
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    │ AS65350 (SDN Domain) │                      │
    │                      ▼                      │
    │  ┌─────────┐   ┌─────────┐                  │
    │  │  ovs1   │───│  ovs2   │←── Peer VXLANs   │
    │  └────┬────┘   └────┬────┘    (34, 36)      │
    │       │             │                       │
    │   ┌───┴───┐     ┌───┴───┐                   │
    │   │anycast1│    │anycast2│                  │
    │   │ h2     │    │ h1     │                  │
    │   │ frr0   │    └────────┘                  │
    │   │ frr1   │                                │
    │   └────────┘                                │
    └─────────────────────────────────────────────┘
```

**Anycast IP**: 172.16.35.100 (shared by anycast1 and anycast2)

**Device IDs**:
- ovs1: `of:0000000000000001`
- ovs2: `of:0000000000000002`

**Host Placement**:
- ovs1: h2, frr0, frr1, anycast1
- ovs2: h1, anycast2, peer VXLANs (34, 36)

## Key Challenges

### Challenge 1: ARP/MAC Learning Race Condition (Internal Hosts)

For internal AS hosts (h1, h2), the learning bridge may cache the wrong anycast server MAC:

**Problem**: When h1 or h2 sends an ARP request for 172.16.35.100, both anycast servers reply. The learning bridge caches whichever MAC arrives last, which may be the farther server.

**Solution Options**:
1. **Proxy ARP for Anycast**: VRouter intercepts ARP for anycast IP and replies with the nearest server's MAC based on ingress port.
2. **Suppress Anycast ARP Replies**: Install flow rules to block anycast server ARP replies, let VRouter handle all ARP for anycast IP.
3. **Source-based Flow Rules**: Install per-source flow rules that match source MAC + anycast destination IP.

---

## Part 1: Infrastructure Setup (Shell Scripts)

### 1.1 Create Anycast Containers (`create.sh` modifications)

Add after existing container creation:

```bash
# --- Anycast Server Containers ---
echo "Creating anycast server containers..."
docker run -d --name anycast1 --hostname anycast1 --network none \
  --cap-add=NET_ADMIN traefik/whoami

docker run -d --name anycast2 --hostname anycast2 --network none \
  --cap-add=NET_ADMIN traefik/whoami

# Connect anycast1 to ovs1 (closer to h2, frr0, frr1)
connect_to_ovs anycast1 ovs1

# Connect anycast2 to ovs2 (closer to h1, peer VXLANs)
connect_to_ovs anycast2 ovs2
```

### 1.2 Configure Anycast IP Addresses (`config.sh` modifications)

Add after existing host configuration:

```bash
# --- Anycast Server Configuration ---
ANYCAST_IP="172.16.${NETWORK_ID}.100"

echo "Configuring anycast servers with shared IP ${ANYCAST_IP}..."
# anycast1 on ovs1 (closer to h2, frr0, frr1)
dexec anycast1 ip addr add ${ANYCAST_IP}/24 dev eth0
dexec anycast1 ip route replace default via 172.16.${NETWORK_ID}.69

# anycast2 on ovs2 (closer to h1, peer VXLANs)
dexec anycast2 ip addr add ${ANYCAST_IP}/24 dev eth0
dexec anycast2 ip route replace default via 172.16.${NETWORK_ID}.69
```

### 1.3 Cleanup Script (`cleanup.sh` modifications)

Add anycast container cleanup:

```bash
docker rm -f anycast1 anycast2 2>/dev/null || true
```

### 1.4 Install HTTP Clients on Hosts (`config.sh` modifications)

Add after host configuration to enable curl/wget for anycast testing:

```bash
# --- Install HTTP clients on hosts ---
echo "Installing curl on hosts for anycast testing..."
# h1 and h2 are Alpine-based (use apk)
dexec h1 apk add --no-cache curl
dexec h2 apk add --no-cache curl
dexec h3 apk add --no-cache curl
```

**Note**: This setup is required before testing anycast functionality with `curl` or `wget`.

---

## Part 2: VRouter Configuration (`config.json` modifications)

Add anycast server connect points configuration:

```json
{
  "apps": {
    "nycu.winlab.vrouter": {
      "vrouter": {
        "anycast-ip": "172.16.35.100",
        "anycast1-connect-point": "of:0000000000000001/X",
        "anycast2-connect-point": "of:0000000000000002/Y"
      }
    }
  }
}
```

**Note**:
- anycast1 is on ovs1 (of:0000000000000001)
- anycast2 is on ovs2 (of:0000000000000002)
- Port numbers (X, Y) will be determined after running `ovs-ofctl show ovs1` and `ovs-ofctl show ovs2` to find the actual port assignments for anycast containers.

---

## Part 3: VRouter Application Changes

### 3.1 VRouterConfig.java - Add Configuration Parsing

Add new parsing methods:

```java
public Ip4Address anycastIp() {
    String ip = get("anycast-ip", null);
    return ip != null ? Ip4Address.valueOf(ip) : null;
}

public ConnectPoint anycast1ConnectPoint() {
    String cp = get("anycast1-connect-point", null);
    return cp != null ? ConnectPoint.deviceConnectPoint(cp) : null;
}

public ConnectPoint anycast2ConnectPoint() {
    String cp = get("anycast2-connect-point", null);
    return cp != null ? ConnectPoint.deviceConnectPoint(cp) : null;
}
```

### 3.2 AppComponent.java - Add Configuration Fields

Add new fields:

```java
// Anycast configuration
private Ip4Address anycastIp;
private ConnectPoint anycast1ConnectPoint;  // on ovs1
private ConnectPoint anycast2ConnectPoint;  // on ovs2
```

### 3.3 AppComponent.java - Load Configuration in readConfig()

Add to `readConfig()` method:

```java
// Load anycast configuration
anycastIp = config.anycastIp();
anycast1ConnectPoint = config.anycast1ConnectPoint();
anycast2ConnectPoint = config.anycast2ConnectPoint();
log.info("Loaded anycast config: ip={}, anycast1={}, anycast2={}",
        anycastIp, anycast1ConnectPoint, anycast2ConnectPoint);
```

### 3.4 AppComponent.java - Anycast Detection

```java
/**
 * Check if the destination IP is the anycast IP.
 */
private boolean isAnycastIp(Ip4Address dstIp) {
    return anycastIp != null && dstIp.equals(anycastIp);
}
```

### 3.5 AppComponent.java - Nearest Server Selection (Core Logic)

```java
/**
 * Selects the nearest anycast server based on ingress point.
 * Uses topology-aware distance calculation.
 *
 * Topology: OVS1 -- OVS2 -- OVS3
 * - anycast1 on ovs1 (of:0000000000000001)
 * - anycast2 on ovs2 (of:0000000000000002)
 *
 * @param ingressCP ConnectPoint where packet arrived
 * @return ConnectPoint of the nearest anycast server
 */
private ConnectPoint selectNearestAnycastServer(ConnectPoint ingressCP) {
    if (anycast1ConnectPoint == null || anycast2ConnectPoint == null) {
        log.warn("Anycast connect points not configured");
        return null;
    }

    DeviceId ingressDevice = ingressCP.deviceId();
    String ingressDevStr = ingressDevice.toString();

    int distanceToAnycast1;  // anycast1 on ovs1
    int distanceToAnycast2;  // anycast2 on ovs2

    if (ingressDevStr.contains("0000000000000001")) {
        // Traffic arrived at ovs1 (h2, frr0, frr1)
        distanceToAnycast1 = 0;  // same switch
        distanceToAnycast2 = 1;  // ovs1 -> ovs2
    } else if (ingressDevStr.contains("0000000000000002")) {
        // Traffic arrived at ovs2 (h1, peer VXLAN)
        distanceToAnycast1 = 1;  // ovs2 -> ovs1
        distanceToAnycast2 = 0;  // same switch
    } else {
        // Unknown device, default to anycast1 (on ovs1)
        log.warn("Unknown ingress device: {}. Defaulting to anycast1.", ingressDevice);
        return anycast1ConnectPoint;
    }

    ConnectPoint selected = (distanceToAnycast1 <= distanceToAnycast2)
        ? anycast1ConnectPoint : anycast2ConnectPoint;

    log.info("Anycast selection: ingress={}, dist1={}, dist2={}, selected={}",
             ingressCP, distanceToAnycast1, distanceToAnycast2, selected);

    return selected;
}
```

### 3.6 AppComponent.java - Get Anycast Server MAC

```java
/**
 * Get the MAC address of the anycast server at the given connect point.
 * Uses HostService to find hosts at that location.
 */
private MacAddress getAnycastServerMac(ConnectPoint serverCp) {
    for (Host host : hostService.getConnectedHosts(serverCp)) {
        for (IpAddress ip : host.ipAddresses()) {
            if (ip.isIp4() && ip.getIp4Address().equals(anycastIp)) {
                return host.mac();
            }
        }
    }
    return null;
}
```

### 3.7 AppComponent.java - Anycast Routing Handler

```java
/**
 * Handle L3 routing to anycast destination.
 * Selects nearest server based on ingress point and routes packet.
 */
private void handleAnycastRouting(PacketContext context, Ethernet eth, ConnectPoint ingressCP) {
    ConnectPoint nearestServer = selectNearestAnycastServer(ingressCP);

    if (nearestServer == null) {
        log.warn("Cannot route anycast: no server configured");
        return;
    }

    MacAddress serverMac = getAnycastServerMac(nearestServer);
    if (serverMac != null) {
        log.info("Anycast L3 routing: ingress={} -> server at {} (MAC={})",
                 ingressCP, nearestServer, serverMac);
        routePacket(context, eth, serverMac);
    } else {
        log.warn("Anycast server MAC not found at {}. Flooding.", nearestServer);
        flood(context);
    }
}
```

### 3.8 AppComponent.java - Modify handleARP()

Add after the virtual gateway IP check in `handleARP()`:

```java
// Check if ARP is for anycast IP
if (isAnycastIp(dstIp)) {
    ConnectPoint nearestServer = selectNearestAnycastServer(srcPoint);

    if (nearestServer != null) {
        MacAddress serverMac = getAnycastServerMac(nearestServer);
        if (serverMac != null) {
            log.info("Anycast ARP REQUEST for {}. Ingress={}, Replying with MAC {}",
                    dstIp, srcPoint, serverMac);
            Ethernet arpPkt = buildArpReply(dstIp, serverMac, srcIp, srcMac);
            packetOut(srcPoint, arpPkt);
            return;
        }
    }
    // Fall through to normal proxy ARP if anycast server MAC not found
}
```

### 3.9 AppComponent.java - Modify handleL3RoutingIPv4()

Add at the beginning of `handleL3RoutingIPv4()`, after extracting dstIp:

```java
// Check if destination is anycast IP
if (isAnycastIp(dstIp)) {
    ConnectPoint ingressCP = context.inPacket().receivedFrom();
    handleAnycastRouting(context, eth, ingressCP);
    return;
}
```

---

## Part 4: Expected Routing Behavior

| Source | Ingress Point | Nearest Server | Reason |
|--------|---------------|----------------|--------|
| h1 | ovs2 | anycast2 (ovs2) | Same switch as h1, distance 0 |
| h2 | ovs1 | anycast1 (ovs1) | Same switch as h2, distance 0 |
| h3 (via frr1) | ovs1 | anycast1 (ovs1) | frr1 connects to ovs1, distance 0 |
| Peer network (via VXLAN) | ovs2 | anycast2 (ovs2) | Peer VXLAN terminates on ovs2, distance 0 |
| WAN (AS65000 via ovs3) | ovs2 | anycast2 (ovs2) | WAN VXLAN terminates on ovs2, distance 0 |

---

## Part 5: Testing Plan

### Basic Connectivity Tests

```bash
# Test from h1 (expect anycast2 - h1 is on ovs2, same as anycast2)
docker exec h1 curl -s http://172.16.35.100
# or: docker exec h1 wget -qO- http://172.16.35.100

# Test from h2 (expect anycast1 - h2 is on ovs1, same as anycast1)
docker exec h2 curl -s http://172.16.35.100
# or: docker exec h2 wget -qO- http://172.16.35.100

# Test from h3 (expect anycast1 - comes via frr1 on ovs1, same as anycast1)
docker exec h3 curl -s http://172.16.35.100
# or: docker exec h3 wget -qO- http://172.16.35.100
```

### Verify ARP Resolution

```bash
# Check ARP tables - each host should have different MAC for same IP
docker exec h1 arp -n | grep 172.16.35.100
docker exec h2 arp -n | grep 172.16.35.100
```

### Check ONOS Logs

```bash
# Check ONOS logs via Apache Karaf client
docker exec -it onos /root/onos/apache-karaf-4.2.14/bin/client log:tail | grep -i anycast
```

### Verify Flow Rules

```bash
ovs-ofctl dump-flows ovs1 -O OpenFlow14 | grep -i "172.16.35.100"
ovs-ofctl dump-flows ovs2 -O OpenFlow14 | grep -i "172.16.35.100"
```

---

## Part 6: File Changes Summary

| File | Changes |
|------|---------|
| `create.sh` | Add anycast container creation and OVS connection |
| `config.sh` | Add anycast IP configuration |
| `cleanup.sh` | Add anycast container cleanup |
| `vrouter/config.json` | Add anycast config (IP, connect points) |
| `vrouter/.../VRouterConfig.java` | Add anycast config parsing methods |
| `vrouter/.../AppComponent.java` | Add anycast detection, selection, routing logic |

---

## Part 7: Implementation Order

1. **Shell Scripts First** - Modify create.sh, config.sh, cleanup.sh
2. **Deploy Topology** - Run `make clean && make deploy`
3. **Determine Port Numbers** - Run:
   ```bash
   ovs-ofctl show ovs1 -O OpenFlow14
   ovs-ofctl show ovs2 -O OpenFlow14
   ```
4. **Update config.json** - Add anycast configuration with correct port numbers
5. **Update VRouterConfig.java** - Add config parsing methods
6. **Update AppComponent.java** - Implement anycast logic
7. **Build and Deploy** -
   ```bash
   cd vrouter
   mvn clean install -DskipTests
   onos-app localhost reinstall! target/vrouter-1.0-SNAPSHOT.oar
   ```
8. **Test** - Verify routing behavior from each source

---

## Troubleshooting

### Anycast server MAC not found
- Ensure anycast containers are running: `docker ps | grep anycast`
- Ping from anycast container to trigger host discovery: `docker exec anycast1 ping -c1 172.16.35.69`
- Check ONOS hosts: `docker exec -it onos /root/onos/apache-karaf-4.2.14/bin/client hosts`

### Wrong server responding
- Check ONOS logs for anycast selection:
  ```bash
  docker exec -it onos /root/onos/apache-karaf-4.2.14/bin/client log:tail | grep "Anycast"
  ```
- Verify connect point configuration matches actual ports
- Clear ARP cache and retry: `docker exec h1 ip neigh flush all`

### No response from anycast IP
- Verify anycast containers have correct IP: `docker exec anycast1 ip addr`
- Check if whoami service is running: `docker exec anycast1 ps aux`
- Test direct connectivity: `docker exec h1 ping 172.16.35.100`
