/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.vrouter;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the VRouter application.
 */
public class VRouterConfig extends Config<ApplicationId> {

    private static final String FRR0_CONNECT_POINT = "frr0-connect-point";
    private static final String FRR1_CONNECT_POINT = "frr1-connect-point";
    private static final String FRR_ZERO_MAC = "frr0-mac";
    private static final String FRR_ZERO_IP4 = "frr0-ip4";
    private static final String FRR_ZERO_IP6 = "frr0-ip6";
    private static final String VIRTUAL_GATEWAY_IP4 = "virtual-gateway-ip4";
    private static final String VIRTUAL_GATEWAY_IP6 = "virtual-gateway-ip6";
    private static final String VIRTUAL_GATEWAY_MAC = "virtual-gateway-mac";
    private static final String WAN_CONNECT_POINT = "wan-connect-point";
    private static final String V4_PEER = "v4-peer";
    private static final String V6_PEER = "v6-peer";
    private static final String PEER1_VXLAN_CP = "peer1-vxlan-cp";
    private static final String PEER2_VXLAN_CP = "peer2-vxlan-cp";
    private static final String PEER1_SDN_PREFIX = "peer1-sdn-prefix";
    private static final String PEER2_SDN_PREFIX = "peer2-sdn-prefix";
    private static final String LOCAL_SDN_PREFIX = "local-sdn-prefix";
    private static final String PEER1_SDN_PREFIX6 = "peer1-sdn-prefix6";
    private static final String PEER2_SDN_PREFIX6 = "peer2-sdn-prefix6";
    private static final String LOCAL_SDN_PREFIX6 = "local-sdn-prefix6";
    private static final String LOCAL_TRADITIONAL_PREFIX = "local-traditional-prefix";
    private static final String LOCAL_TRADITIONAL_PREFIX6 = "local-traditional-prefix6";
    private static final String PEER1_TRADITIONAL_PREFIX = "peer1-traditional-prefix";
    private static final String PEER2_TRADITIONAL_PREFIX = "peer2-traditional-prefix";
    private static final String PEER1_TRADITIONAL_PREFIX6 = "peer1-traditional-prefix6";
    private static final String PEER2_TRADITIONAL_PREFIX6 = "peer2-traditional-prefix6";
    private static final String INGRESS_FILTERS = "ingress-filters";
    private static final String ARP_INGRESS_FILTERS = "arp-ingress-filters";

    @Override
    public boolean isValid() {
        return hasOnlyFields(FRR0_CONNECT_POINT, FRR1_CONNECT_POINT, FRR_ZERO_MAC, FRR_ZERO_IP4, FRR_ZERO_IP6,
                VIRTUAL_GATEWAY_IP4, VIRTUAL_GATEWAY_IP6,
                VIRTUAL_GATEWAY_MAC, WAN_CONNECT_POINT, V4_PEER, V6_PEER,
                PEER1_VXLAN_CP, PEER2_VXLAN_CP, PEER1_SDN_PREFIX, PEER2_SDN_PREFIX, LOCAL_SDN_PREFIX,
                PEER1_SDN_PREFIX6, PEER2_SDN_PREFIX6, LOCAL_SDN_PREFIX6,
                LOCAL_TRADITIONAL_PREFIX, LOCAL_TRADITIONAL_PREFIX6,
                PEER1_TRADITIONAL_PREFIX, PEER2_TRADITIONAL_PREFIX,
                PEER1_TRADITIONAL_PREFIX6, PEER2_TRADITIONAL_PREFIX6,
                INGRESS_FILTERS, ARP_INGRESS_FILTERS);
    }

    /**
     * Gets the FRR0 connect point.
     *
     * @return ConnectPoint or null if not configured
     */
    public ConnectPoint frr0ConnectPoint() {
        String port = get(FRR0_CONNECT_POINT, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }

    /**
     * Gets the FRR1 connect point.
     *
     * @return ConnectPoint or null if not configured
     */
    public ConnectPoint frr1ConnectPoint() {
        String port = get(FRR1_CONNECT_POINT, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }

    /**
     * Gets the Quagga/FRR router MAC address.
     *
     * @return MAC address or null if not configured
     */
    public MacAddress frr0Mac() {
        String mac = get(FRR_ZERO_MAC, null);
        return mac != null ? MacAddress.valueOf(mac) : null;
    }

    /**
     * Gets the Quagga/FRR router IPv4 address.
     *
     * @return IPv4 address or null if not configured
     */
    public Ip4Address frr0Ip4() {
        String ip = get(FRR_ZERO_IP4, null);
        return ip != null ? Ip4Address.valueOf(ip) : null;
    }

    /**
     * Gets the Quagga/FRR router IPv6 address.
     *
     * @return IPv6 address or null if not configured
     */
    public Ip6Address frr0Ip6() {
        String ip = get(FRR_ZERO_IP6, null);
        return ip != null ? Ip6Address.valueOf(ip) : null;
    }

    /**
     * Gets the virtual gateway IPv4 address.
     *
     * @return IPv4 address or null if not configured
     */
    public Ip4Address virtualGatewayIp4() {
        String ip = get(VIRTUAL_GATEWAY_IP4, null);
        return ip != null ? Ip4Address.valueOf(ip) : null;
    }

    /**
     * Gets the virtual gateway IPv6 address.
     *
     * @return IPv6 address or null if not configured
     */
    public Ip6Address virtualGatewayIp6() {
        String ip = get(VIRTUAL_GATEWAY_IP6, null);
        return ip != null ? Ip6Address.valueOf(ip) : null;
    }

    /**
     * Gets the virtual gateway MAC address.
     *
     * @return MAC address or null if not configured
     */
    public MacAddress virtualGatewayMac() {
        String mac = get(VIRTUAL_GATEWAY_MAC, null);
        return mac != null ? MacAddress.valueOf(mac) : null;
    }

    /**
     * Gets the external port (interface port) where ARP/NDP should be dropped.
     *
     * @return ConnectPoint or null if not configured
     */
    public ConnectPoint externalPort() {
        String port = get(WAN_CONNECT_POINT, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }

    /**
     * Gets the peer 1 VXLAN connect point.
     *
     * @return ConnectPoint or null if not configured
     */
    public ConnectPoint peer1VxlanCp() {
        String port = get(PEER1_VXLAN_CP, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }

    /**
     * Gets the peer 2 VXLAN connect point.
     *
     * @return ConnectPoint or null if not configured
     */
    public ConnectPoint peer2VxlanCp() {
        String port = get(PEER2_VXLAN_CP, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }

    /**
     * Gets the peer 1 SDN network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer1SdnPrefix() {
        String prefix = get(PEER1_SDN_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 2 SDN network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer2SdnPrefix() {
        String prefix = get(PEER2_SDN_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the local SDN network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix localSdnPrefix() {
        String prefix = get(LOCAL_SDN_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 1 SDN IPv6 network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer1SdnPrefix6() {
        String prefix = get(PEER1_SDN_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 2 SDN IPv6 network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer2SdnPrefix6() {
        String prefix = get(PEER2_SDN_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the local SDN IPv6 network prefix.
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix localSdnPrefix6() {
        String prefix = get(LOCAL_SDN_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the local traditional network prefix (e.g., 172.17.35.0/24).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix localTraditionalPrefix() {
        String prefix = get(LOCAL_TRADITIONAL_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the local traditional IPv6 network prefix (e.g., 2a0b:4e07:c4:135::/64).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix localTraditionalPrefix6() {
        String prefix = get(LOCAL_TRADITIONAL_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 1 traditional network prefix (e.g., 172.17.34.0/24).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer1TraditionalPrefix() {
        String prefix = get(PEER1_TRADITIONAL_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 2 traditional network prefix (e.g., 172.17.36.0/24).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer2TraditionalPrefix() {
        String prefix = get(PEER2_TRADITIONAL_PREFIX, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 1 traditional IPv6 network prefix (e.g., 2a0b:4e07:c4:134::/64).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer1TraditionalPrefix6() {
        String prefix = get(PEER1_TRADITIONAL_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the peer 2 traditional IPv6 network prefix (e.g., 2a0b:4e07:c4:136::/64).
     *
     * @return IpPrefix or null if not configured
     */
    public IpPrefix peer2TraditionalPrefix6() {
        String prefix = get(PEER2_TRADITIONAL_PREFIX6, null);
        return prefix != null ? IpPrefix.valueOf(prefix) : null;
    }

    /**
     * Gets the list of IPv4 peer pairs (local IP, remote IP).
     * Config format: ["192.168.70.35, 192.168.70.253"]
     *
     * @return List of String arrays [localIp, remoteIp], or empty list if not configured
     */
    public List<String[]> v4Peers() {
        List<String[]> peers = new ArrayList<>();
        if (!hasField(V4_PEER)) {
            return peers;
        }

        // Get the array from config
        for (String peerEntry : getStringList(V4_PEER)) {
            String[] parts = peerEntry.split(",");
            if (parts.length == 2) {
                peers.add(new String[]{parts[0].trim(), parts[1].trim()});
            }
        }
        return peers;
    }

    /**
     * Gets the list of IPv6 peer pairs (local IP, remote IP).
     * Config format: ["fd70::35, fd70::fe"]
     *
     * @return List of String arrays [localIp, remoteIp], or empty list if not configured
     */
    public List<String[]> v6Peers() {
        List<String[]> peers = new ArrayList<>();
        if (!hasField(V6_PEER)) {
            return peers;
        }

        // Get the array from config
        for (String peerEntry : getStringList(V6_PEER)) {
            String[] parts = peerEntry.split(",");
            if (parts.length == 2) {
                peers.add(new String[]{parts[0].trim(), parts[1].trim()});
            }
        }
        return peers;
    }

    private List<String> getStringList(String key) {
        List<String> result = new ArrayList<>();
        if (node.has(key) && node.get(key).isArray()) {
            node.get(key).forEach(item -> result.add(item.asText()));
        }
        return result;
    }

    /**
     * Gets the ingress filter allowlist for a specific connect point.
     * Config format:
     * "ingress-filters": {
     *   "of:0000000000000002/4": ["172.16.35.0/24", "192.168.70.35/32"],
     *   "of:0000ceaa83f3a445/3": ["172.17.35.0/24", "192.168.70.35/32"]
     * }
     *
     * @param connectPoint the connect point to get filters for
     * @return List of allowed IpPrefix, or empty list if not configured
     */
    public List<IpPrefix> ingressFilters(ConnectPoint connectPoint) {
        List<IpPrefix> prefixes = new ArrayList<>();
        if (!hasField(INGRESS_FILTERS)) {
            return prefixes;
        }

        String cpKey = connectPoint.toString();
        if (node.has(INGRESS_FILTERS) && node.get(INGRESS_FILTERS).has(cpKey)) {
            node.get(INGRESS_FILTERS).get(cpKey).forEach(item -> {
                try {
                    prefixes.add(IpPrefix.valueOf(item.asText()));
                } catch (IllegalArgumentException e) {
                    // Skip invalid prefix
                }
            });
        }
        return prefixes;
    }

    /**
     * Gets the ARP ingress filter allowlist for a specific connect point.
     * Config format:
     * "arp-ingress-filters": {
     *   "of:0000000000000002/4": ["192.168.70.35/32"],
     *   "of:0000ceaa83f3a445/3": ["192.168.70.35/32"]
     * }
     *
     * @param connectPoint the connect point to get ARP filters for
     * @return List of allowed IpPrefix for ARP target IPs, or empty list if not configured
     */
    public List<IpPrefix> arpIngressFilters(ConnectPoint connectPoint) {
        List<IpPrefix> prefixes = new ArrayList<>();
        if (!hasField(ARP_INGRESS_FILTERS)) {
            return prefixes;
        }

        String cpKey = connectPoint.toString();
        if (node.has(ARP_INGRESS_FILTERS) && node.get(ARP_INGRESS_FILTERS).has(cpKey)) {
            node.get(ARP_INGRESS_FILTERS).get(cpKey).forEach(item -> {
                try {
                    prefixes.add(IpPrefix.valueOf(item.asText()));
                } catch (IllegalArgumentException e) {
                    // Skip invalid prefix
                }
            });
        }
        return prefixes;
    }
}
