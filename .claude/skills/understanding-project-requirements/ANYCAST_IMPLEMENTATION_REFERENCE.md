# Anycast Server Implementation Reference

## Implementation Idea On Similar Topology
```
/**
 * Selects the nearest host from a set of anycast hosts.
 * Uses topology-aware distance calculation.
 * 
 * @param hosts Set of hosts with the same IP address
 * @param ingressCP ConnectPoint where packet arrived
 * @return Host that is topologically closest to ingress
 */
private Host selectNearestHost(Set<Host> hosts, ConnectPoint ingressCP) {
    if (hosts.isEmpty()) {
        return null;
    }
    
    if (hosts.size() == 1) {
        return hosts.iterator().next();
    }
    
    // Multiple hosts - select nearest one
    Host selectedHost = null;
    int minDistance = Integer.MAX_VALUE;
    
    DeviceId ingressDevice = ingressCP.deviceId();
    String ingressDevStr = ingressDevice.toString();
    
    for (Host h : hosts) {
        DeviceId hostDevice = h.location().deviceId();
        String hostDevStr = hostDevice.toString();
        
        int distance;
        
        // Same switch = distance 0
        if (ingressDevice.equals(hostDevice)) {
            distance = 0;
            log.info("Anycast: Host {} on same switch as ingress", h.mac());
        }
        // Topology-specific distance calculation for your 3-switch setup
        // OVS1 -- OVS2 -- OVS3
        else if ((ingressDevStr.contains("ovs1") && hostDevStr.contains("ovs2")) ||
                 (ingressDevStr.contains("ovs2") && hostDevStr.contains("ovs1"))) {
            distance = 1;  // OVS1 ↔ OVS2 direct connection
        }
        else if ((ingressDevStr.contains("ovs2") && hostDevStr.contains("ovs3")) ||
                 (ingressDevStr.contains("ovs3") && hostDevStr.contains("ovs2"))) {
            distance = 1;  // OVS2 ↔ OVS3 direct connection
        }
        else if ((ingressDevStr.contains("ovs1") && hostDevStr.contains("ovs3")) ||
                 (ingressDevStr.contains("ovs3") && hostDevStr.contains("ovs1"))) {
            distance = 2;  // OVS1 ↔ OVS3 via OVS2
        }
        else {
            // Unknown topology, use default distance
            distance = 10;
            log.warn("Anycast: Unknown switch pair {} and {}", ingressDevice, hostDevice);
        }
        
        if (distance < minDistance) {
            minDistance = distance;
            selectedHost = h;
        }
    }
    
    log.info("Anycast: Selected host {} at distance {} from ingress {}", 
             selectedHost.location(), minDistance, ingressCP);
    
    return selectedHost;
}
```