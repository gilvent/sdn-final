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

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.serializers.KryoNamespaces;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.routeservice.RouteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Virtual Router ONOS application combining ProxyARP/NDP and Learning Bridge.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry configRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private final InternalConfigListener configListener = new InternalConfigListener();
    private final ConfigFactory<ApplicationId, VRouterConfig> configFactory =
            new ConfigFactory<ApplicationId, VRouterConfig>(
                    SubjectFactories.APP_SUBJECT_FACTORY,
                    VRouterConfig.class,
                    "vrouter") {
                @Override
                public VRouterConfig createConfig() {
                    return new VRouterConfig();
                }
            };

    // Virtual gateway configuration
    private Ip4Address virtualGatewayIp4;
    private Ip6Address virtualGatewayIp6;
    private MacAddress virtualGatewayMac;

    // Quagga/FRR router configuration (for default routing)
    private MacAddress frr0Mac;
    private Ip4Address frr0Ip4;
    private Ip6Address frr0Ip6;

    // External port (interface port) where ARP/NDP should be dropped
    private ConnectPoint externalPort;

    // WAN peering configuration (for AS65000, AS65340, AS65360 BGP)
    private Ip4Address wanLocalIp4;       // frr0's IP on WAN subnet (192.168.70.35)
    private List<Ip4Address> wanPeerIp4List = new ArrayList<>();  // BGP peer IPs (AS65000, AS65340, AS65360)
    private ConnectPoint frr0ConnectPoint; // Connect point where frr0 is connected
    private ConnectPoint frr1ConnectPoint; // Connect point where frr1 is connected

    // WAN IPv6 peering configuration (for AS65000, AS65340, AS65360 BGP over IPv6)
    private Ip6Address wanLocalIp6;       // frr0's IPv6 on WAN subnet (fd70::35)
    private List<Ip6Address> wanPeerIp6List = new ArrayList<>();  // BGP peer IPv6s

    // Internal IPv6 peer configuration (for inter-AS BGP, e.g., frr0 <-> frr1)
    // Stores pairs of [localIp, peerIp] for internal BGP peering
    private List<Ip6Address[]> internalV6Peers = new ArrayList<>();

    // Peer VXLAN configuration (for peer network communication)
    private ConnectPoint peer1VxlanCp;
    private ConnectPoint peer2VxlanCp;
    private IpPrefix peer1SdnPrefix;
    private IpPrefix peer2SdnPrefix;
    private IpPrefix localSdnPrefix;
    private IpPrefix peer1SdnPrefix6;
    private IpPrefix peer2SdnPrefix6;
    private IpPrefix localSdnPrefix6;
    private MacAddress peer1GatewayMac;
    private MacAddress peer2GatewayMac;

    private ConsistentMap<Ip4Address, MacAddress> ipToMacTable;
    private ConsistentMap<Ip6Address, MacAddress> ip6ToMacTable;
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();

    private ApplicationId appId;

    private VRouterPacketProcessor processor = new VRouterPacketProcessor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.vrouter");

        // Register config factory and listener
        configRegistry.addListener(configListener);
        configRegistry.registerConfigFactory(configFactory);

        // Initialize ARP/NDP tables BEFORE loading config (so pre-population works)
        ipToMacTable = storageService.<Ip4Address, MacAddress>consistentMapBuilder()
                .withName("ip-mac-table")
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .build();

        ip6ToMacTable = storageService.<Ip6Address, MacAddress>consistentMapBuilder()
                .withName("ipv6-mac-table")
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .build();

        // Load existing configuration (after tables are created)
        readConfig();

        // Request packet-in for IPv4 and IPv6
        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder arpSelector = DefaultTrafficSelector.builder();
        arpSelector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(arpSelector.build(), PacketPriority.REACTIVE, appId);

        packetService.addProcessor(processor, PacketProcessor.director(2));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        configRegistry.removeListener(configListener);
        configRegistry.unregisterConfigFactory(configFactory);

        // Withdraw all intents created by this app
        for (Intent intent : intentService.getIntents()) {
            if (intent.appId().equals(appId)) {
                intentService.withdraw(intent);
            }
        }

        flowRuleService.removeFlowRulesById(appId);

        packetService.removeProcessor(processor);
        processor = null;

        TrafficSelector.Builder ipv4Selector = DefaultTrafficSelector.builder();
        ipv4Selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(ipv4Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder ipv6Selector = DefaultTrafficSelector.builder();
        ipv6Selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(ipv6Selector.build(), PacketPriority.REACTIVE, appId);

        TrafficSelector.Builder arpSelector = DefaultTrafficSelector.builder();
        arpSelector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(arpSelector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        log.info("Reconfigured");
    }

    private void readConfig() {
        VRouterConfig config = configRegistry.getConfig(appId, VRouterConfig.class);
        if (config != null) {
            virtualGatewayIp4 = config.virtualGatewayIp4();
            virtualGatewayIp6 = config.virtualGatewayIp6();
            virtualGatewayMac = config.virtualGatewayMac();
            frr0Mac = config.frr0Mac();
            frr0Ip4 = config.frr0Ip4();
            frr0Ip6 = config.frr0Ip6();
            externalPort = config.externalPort();
            frr0ConnectPoint = config.frr0ConnectPoint();
            frr1ConnectPoint = config.frr1ConnectPoint();
            log.info("Loaded VRouter config: gateway-ip4={}, gateway-ip6={}, gateway-mac={}",
                    virtualGatewayIp4, virtualGatewayIp6, virtualGatewayMac);
            log.info("Loaded Quagga config: frr0-mac={}, frr0-ip4={}, frr0-ip6={}",
                    frr0Mac, frr0Ip4, frr0Ip6);
            log.info("Loaded external port config: wan-connect-point={}", externalPort);
            log.info("Loaded frr0 connect point: {}", frr0ConnectPoint);
            log.info("Loaded frr1 connect point: {}", frr1ConnectPoint);

            // Parse v4-peer to get WAN local and all peer IPs
            List<String[]> v4Peers = config.v4Peers();
            if (v4Peers != null && !v4Peers.isEmpty()) {
                // First entry sets local IP
                String[] firstPeer = v4Peers.get(0);
                wanLocalIp4 = Ip4Address.valueOf(firstPeer[0]);

                // Clear previous peers and add all peer IPs
                wanPeerIp4List.clear();
                for (String[] peer : v4Peers) {
                    Ip4Address peerIp = Ip4Address.valueOf(peer[1]);
                    wanPeerIp4List.add(peerIp);
                    log.info("Loaded WAN v4 peer: local={}, peer={}", peer[0], peerIp);
                }
            }

            // Pre-populate frr0 IP-MAC mappings for L3 routing
            if (frr0Ip4 != null && frr0Mac != null && ipToMacTable != null) {
                ipToMacTable.put(frr0Ip4, frr0Mac);
                log.info("Pre-populated frr0 IPv4 mapping: {} -> {}", frr0Ip4, frr0Mac);
            }
            if (frr0Ip6 != null && frr0Mac != null && ip6ToMacTable != null) {
                ip6ToMacTable.put(frr0Ip6, frr0Mac);
                log.info("Pre-populated frr0 IPv6 mapping: {} -> {}", frr0Ip6, frr0Mac);
            }

            // Pre-populate WAN local IP -> frr0 MAC mapping
            if (wanLocalIp4 != null && frr0Mac != null && ipToMacTable != null) {
                ipToMacTable.put(wanLocalIp4, frr0Mac);
                log.info("Pre-populated WAN local IPv4 mapping: {} -> {}", wanLocalIp4, frr0Mac);
            }

            // Parse v6-peer to get WAN IPv6 and internal peer addresses
            // Format: ["fd70::35, fd70::fe", "fd70::35, fd70::34", "fd70::35, fd70::36", "fd63::1, fd63::2"]
            // Entries with same /64 prefix as first entry's local IP are WAN peers, others are internal
            List<String[]> v6Peers = config.v6Peers();
            if (v6Peers != null && !v6Peers.isEmpty()) {
                // First entry sets local IP for WAN subnet
                String[] firstPeer = v6Peers.get(0);
                wanLocalIp6 = Ip6Address.valueOf(firstPeer[0]);

                // Clear previous peers
                wanPeerIp6List.clear();
                internalV6Peers.clear();

                // Classify peers based on /64 subnet
                for (String[] peer : v6Peers) {
                    Ip6Address localIp = Ip6Address.valueOf(peer[0]);
                    Ip6Address peerIp = Ip6Address.valueOf(peer[1]);

                    // Check if this is a WAN peer (same /64 as wanLocalIp6)
                    if (isSameSubnet64(localIp, wanLocalIp6)) {
                        wanPeerIp6List.add(peerIp);
                        log.info("Loaded WAN IPv6 peer: local={}, peer={}", localIp, peerIp);
                    } else {
                        // This is an internal peer
                        internalV6Peers.add(new Ip6Address[]{localIp, peerIp});
                        log.info("Loaded internal IPv6 peering config: local={}, peer={}", localIp, peerIp);
                    }
                }
            }

            // Pre-populate WAN local IPv6 -> frr0 MAC mapping
            if (wanLocalIp6 != null && frr0Mac != null && ip6ToMacTable != null) {
                ip6ToMacTable.put(wanLocalIp6, frr0Mac);
                log.info("Pre-populated WAN local IPv6 mapping: {} -> {}", wanLocalIp6, frr0Mac);
            }

            // Pre-populate internal peer IPv6 -> frr0 MAC mapping (for frr0's internal IPs)
            for (Ip6Address[] peerPair : internalV6Peers) {
                Ip6Address localIp = peerPair[0];
                if (frr0Mac != null && ip6ToMacTable != null) {
                    ip6ToMacTable.put(localIp, frr0Mac);
                    log.info("Pre-populated internal IPv6 mapping: {} -> {}", localIp, frr0Mac);
                }
            }

            // Install WAN forwarding intents
            installWanForwardingIntents();

            // Install internal peer forwarding intents
            installInternalPeerForwardingIntents();

            // Load peer VXLAN configuration
            peer1VxlanCp = config.peer1VxlanCp();
            peer2VxlanCp = config.peer2VxlanCp();
            peer1SdnPrefix = config.peer1SdnPrefix();
            peer2SdnPrefix = config.peer2SdnPrefix();
            localSdnPrefix = config.localSdnPrefix();
            log.info("Loaded peer VXLAN config: peer1-cp={}, peer2-cp={}", peer1VxlanCp, peer2VxlanCp);
            log.info("Loaded peer SDN prefixes: peer1={}, peer2={}, local={}",
                    peer1SdnPrefix, peer2SdnPrefix, localSdnPrefix);

            // Load peer IPv6 SDN prefixes
            peer1SdnPrefix6 = config.peer1SdnPrefix6();
            peer2SdnPrefix6 = config.peer2SdnPrefix6();
            localSdnPrefix6 = config.localSdnPrefix6();
            log.info("Loaded peer IPv6 SDN prefixes: peer1={}, peer2={}, local={}",
                    peer1SdnPrefix6, peer2SdnPrefix6, localSdnPrefix6);

            // Load peer gateway MACs
            peer1GatewayMac = config.peer1GatewayMac();
            peer2GatewayMac = config.peer2GatewayMac();
            log.info("Loaded peer gateway MACs: peer1={}, peer2={}",
                    peer1GatewayMac, peer2GatewayMac);
        }
    }

    private class InternalConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if (event.configClass().equals(VRouterConfig.class)) {
                switch (event.type()) {
                    case CONFIG_ADDED:
                    case CONFIG_UPDATED:
                        readConfig();
                        break;
                    default:
                        break;
                }
            }
        }
    }

    /**
     * Check if two IPv6 addresses are in the same /64 subnet.
     */
    private boolean isSameSubnet64(Ip6Address ip1, Ip6Address ip2) {
        byte[] bytes1 = ip1.toOctets();
        byte[] bytes2 = ip2.toOctets();

        // Compare first 8 bytes (64 bits)
        for (int i = 0; i < 8; i++) {
            if (bytes1[i] != bytes2[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if the connect point is a peer VXLAN port.
     */
    private boolean isPeerVxlanPort(ConnectPoint cp) {
        return (peer1VxlanCp != null && cp.equals(peer1VxlanCp)) ||
               (peer2VxlanCp != null && cp.equals(peer2VxlanCp));
    }

    /**
     * Get the peer VXLAN connect point for a destination IP.
     * Returns null if destination is not in any peer SDN prefix.
     */
    private ConnectPoint getPeerVxlanForDestination(Ip4Address dstIp) {
        if (peer1SdnPrefix != null && peer1VxlanCp != null &&
                peer1SdnPrefix.contains(IpAddress.valueOf(dstIp.toString()))) {
            return peer1VxlanCp;
        }
        if (peer2SdnPrefix != null && peer2VxlanCp != null &&
                peer2SdnPrefix.contains(IpAddress.valueOf(dstIp.toString()))) {
            return peer2VxlanCp;
        }
        return null;
    }

    /**
     * Get the peer VXLAN connect point for an IPv6 destination.
     * Returns null if destination is not in any peer SDN prefix.
     */
    private ConnectPoint getPeerVxlanForDestinationV6(Ip6Address dstIp) {
        if (peer1SdnPrefix6 != null && peer1VxlanCp != null &&
                peer1SdnPrefix6.contains(IpAddress.valueOf(dstIp.toString()))) {
            return peer1VxlanCp;
        }
        if (peer2SdnPrefix6 != null && peer2VxlanCp != null &&
                peer2SdnPrefix6.contains(IpAddress.valueOf(dstIp.toString()))) {
            return peer2VxlanCp;
        }
        return null;
    }

    /**
     * Get the gateway MAC address for a peer VXLAN connect point.
     * Returns the peer-specific gateway MAC if configured, otherwise falls back to virtualGatewayMac.
     *
     * @param peerCp The peer VXLAN connect point
     * @return Gateway MAC address for the peer, or virtualGatewayMac if not configured
     */
    private MacAddress getPeerGatewayMac(ConnectPoint peerCp) {
        if (peer1VxlanCp != null && peerCp.equals(peer1VxlanCp)) {
            return peer1GatewayMac != null ? peer1GatewayMac : virtualGatewayMac;
        }
        if (peer2VxlanCp != null && peerCp.equals(peer2VxlanCp)) {
            return peer2GatewayMac != null ? peer2GatewayMac : virtualGatewayMac;
        }
        log.warn("Unknown peer VXLAN CP: {}. Using virtualGatewayMac", peerCp);
        return virtualGatewayMac;
    }

    private class VRouterPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            if (virtualGatewayIp4 == null || virtualGatewayMac == null) {
                log.warn("VRouter config not yet loaded. Dropping packet.",
                         virtualGatewayIp4, virtualGatewayMac);
                return;
            }

            InboundPacket inPkt = context.inPacket();
            Ethernet eth = inPkt.parsed();

            if (eth == null) {
                return;
            }

            if (eth.getEtherType() == Ethernet.TYPE_LLDP) {
                return;
            }

            // Handle ARP packets
            if (eth.getEtherType() == Ethernet.TYPE_ARP) {
                handleARP(context, eth);
                return;
            }

            // Handle IPv4 packets
            if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                ConnectPoint srcPoint = context.inPacket().receivedFrom();

                // Handle incoming IPv4 from peer VXLAN ports
                if (isPeerVxlanPort(srcPoint)) {
                    handleIncomingPeerVxlanIPv4(context, eth);
                    return;
                }

                // Block IPv4 from WAN port that isn't destined for frr0's WAN IP
                if (externalPort != null && srcPoint.equals(externalPort)) {
                    IPv4 ipv4 = (IPv4) eth.getPayload();
                    Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
                    if (wanLocalIp4 == null || !dstIp.equals(wanLocalIp4)) {
                        // Drop external IPv4 traffic not destined for frr0
                        return;
                    }
                    // Traffic to frr0's WAN IP - forward to frr0
                    if (frr0ConnectPoint != null) {
                        packetOut(frr0ConnectPoint, eth);
                    }
                    return;
                }

                // Handle IPv4 traffic FROM frr0 TO WAN peers (outbound BGP traffic)
                if (frr0ConnectPoint != null && srcPoint.equals(frr0ConnectPoint) && !wanPeerIp4List.isEmpty()) {
                    IPv4 ipv4 = (IPv4) eth.getPayload();
                    Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());

                    // Forward traffic destined to any WAN peer to external port
                    for (Ip4Address peerIp : wanPeerIp4List) {
                        if (dstIp.equals(peerIp)) {
                            log.info("Forwarding frr0 IPv4 to WAN peer {}: {} -> {}", peerIp, frr0ConnectPoint, externalPort);
                            packetOut(externalPort, eth);
                            return;
                        }
                    }
                }

                // Check if this is L3 routing (destination is our virtual gateway MAC)
                if (virtualGatewayMac != null && eth.getDestinationMAC().equals(virtualGatewayMac)) {
                    handleL3RoutingIPv4(context, eth);
                    return;
                }
                handleLearningBridge(context, eth);
                return;
            }

            // Handle IPv6 packets
            if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
                ConnectPoint srcPoint = context.inPacket().receivedFrom();
                IPv6 ipv6 = (IPv6) eth.getPayload();

                // Handle incoming IPv6 from peer VXLAN ports
                if (isPeerVxlanPort(srcPoint)) {
                    handleIncomingPeerVxlanIPv6(context, eth);
                    return;
                }

                // Handle traffic FROM WAN port (inbound)
                if (externalPort != null && srcPoint.equals(externalPort)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

                    // Allow NDP (handled by handleWanNDP via handleNDP)
                    if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                        ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                        byte type = icmp6.getIcmpType();
                        if (type == ICMP6.NEIGHBOR_SOLICITATION || type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                            handleNDP(context, eth);
                            return;
                        }
                    }

                    // Block non-NDP IPv6 not destined for frr0
                    if (wanLocalIp6 == null || !dstIp.equals(wanLocalIp6)) {
                        log.debug("Blocking WAN IPv6 not for frr0: dstIp={}", dstIp);
                        return;
                    }

                    // Traffic to frr0's WAN IPv6 - forward to frr0
                    if (frr0ConnectPoint != null) {
                        log.info("Forwarding WAN IPv6 to frr0: {} -> {}", dstIp, frr0ConnectPoint);
                        packetOut(frr0ConnectPoint, eth);
                    }
                    return;
                }

                // Handle traffic TO WAN port (outbound from frr0)
                if (!wanPeerIp6List.isEmpty() && frr0ConnectPoint != null && srcPoint.equals(frr0ConnectPoint)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

                    // Forward traffic destined to any WAN peer to external port
                    for (Ip6Address peerIp : wanPeerIp6List) {
                        if (dstIp.equals(peerIp)) {
                            log.info("Forwarding frr0 IPv6 to WAN peer {}: {} -> {}", peerIp, frr0ConnectPoint, externalPort);
                            packetOut(externalPort, eth);
                            return;
                        }
                    }
                }

                // Handle NDP (Neighbor Solicitation and Advertisement)
                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte type = icmp6.getIcmpType();
                    if (type == ICMP6.NEIGHBOR_SOLICITATION || type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        handleNDP(context, eth);
                        return;
                    }
                }

                // Check if this is L3 routing (destination is our virtual gateway MAC)
                if (virtualGatewayMac != null && eth.getDestinationMAC().equals(virtualGatewayMac)) {
                    handleL3RoutingIPv6(context, eth);
                    return;
                }

                // Handle other IPv6 traffic with learning bridge
                handleLearningBridge(context, eth);
                return;
            }
        }
    }

    private void packetOut(ConnectPoint outCp, Ethernet eth) {
        OutboundPacket pkt = new DefaultOutboundPacket(
                outCp.deviceId(),
                DefaultTrafficTreatment.builder().setOutput(outCp.port()).build(),
                ByteBuffer.wrap(eth.serialize()));

        packetService.emit(pkt);
    }

    private Ethernet buildArpReply(Ip4Address senderIp, MacAddress senderMac,
            Ip4Address targetIp, MacAddress targetMac) {
        ARP arpReply = new ARP();
        arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setHardwareAddressLength((byte) MacAddress.MAC_ADDRESS_LENGTH)
                .setProtocolAddressLength((byte) Ip4Address.BYTE_LENGTH)
                .setOpCode(ARP.OP_REPLY)
                .setSenderHardwareAddress(senderMac.toBytes())
                .setSenderProtocolAddress(senderIp.toOctets())
                .setTargetHardwareAddress(targetMac.toBytes())
                .setTargetProtocolAddress(targetIp.toOctets());

        Ethernet ethPkt = new Ethernet();
        ethPkt.setEtherType(Ethernet.TYPE_ARP)
                .setSourceMACAddress(senderMac)
                .setDestinationMACAddress(targetMac)
                .setVlanID(VlanId.NONE.toShort())
                .setPayload(arpReply);

        return ethPkt;
    }

    public ConnectPoint findHostEdgePoint(MacAddress dstMac) {
        HostId hostId = HostId.hostId(dstMac, VlanId.NONE);
        Host host = hostService.getHost(hostId);

        if (host == null) {
            return null;
        }

        HostLocation loc = host.location();
        return new ConnectPoint(loc.deviceId(), loc.port());
    }

    

    private void handleARP(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();

        // Block ALL ARP from peer VXLAN ports (L3 routing - no ARP needed across VXLAN)
        if (isPeerVxlanPort(srcPoint)) {
            log.debug("Blocked ARP from peer VXLAN port {}", srcPoint);
            return;
        }

        // Handle ARP packets from WAN port separately
        if (externalPort != null && srcPoint.equals(externalPort)) {
            handleWanARP(context, eth);
            return;
        }

        MacAddress srcMac = eth.getSourceMAC();
        ARP arp = (ARP) eth.getPayload();
        Ip4Address srcIp = Ip4Address.valueOf(arp.getSenderProtocolAddress());
        Ip4Address dstIp = Ip4Address.valueOf(arp.getTargetProtocolAddress());

        DeviceId deviceId = srcPoint.deviceId();
        PortNumber srcPort = srcPoint.port();

        // Learn IP and MAC of sender host
        ipToMacTable.put(srcIp, srcMac);

        // Also learn MAC-port mapping in bridgeTable (critical for L3 routing)
        if (bridgeTable.get(deviceId) == null) {
            bridgeTable.put(deviceId, new HashMap<>());
        }
        bridgeTable.get(deviceId).put(srcMac, srcPort);

        if (arp.getOpCode() == ARP.OP_REPLY) {
            MacAddress cachedDstMac = ipToMacTable.asJavaMap().get(dstIp);
            ConnectPoint dstHostPoint = findHostEdgePoint(cachedDstMac);

            if (dstHostPoint != null) {
                packetOut(dstHostPoint, eth);
            }
            return;
        }

        if (arp.getOpCode() == ARP.OP_REQUEST) {
            // Check if ARP is for our virtual gateway IP
            log.info("ARP REQUEST for {}. from {}",
                        dstIp, srcIp);
            if (virtualGatewayIp4 != null && dstIp.equals(virtualGatewayIp4)) {
                log.info("ARP REQUEST for virtual gateway IP {}. Replying with MAC {}",
                        virtualGatewayIp4, virtualGatewayMac);

                Ethernet arpPkt = buildArpReply(dstIp, virtualGatewayMac, srcIp, srcMac);
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, arpPkt);
                return;
            }

            // Check if ARP target is any WAN peer IP - forward to WAN port
            if (externalPort != null && !wanPeerIp4List.isEmpty()) {
                for (Ip4Address peerIp : wanPeerIp4List) {
                    if (dstIp.equals(peerIp)) {
                        log.info("Forwarding ARP Request for WAN peer {} to WAN port", dstIp);
                        packetOut(externalPort, eth);
                        return;
                    }
                }
            }

            // Handle ProxyARP
            MacAddress cachedDstMac = ipToMacTable.asJavaMap().get(dstIp);

            if (cachedDstMac != null) {
                log.info("ARP TABLE HIT. Requested MAC = {}", cachedDstMac);

                Ethernet arpPkt = buildArpReply(dstIp, cachedDstMac, srcIp, srcMac);
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, arpPkt);
            } else {
                log.info("ARP TABLE MISS: {}. Send request to edge ports", dstIp);

                Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

                for (ConnectPoint cp : edgePoints) {
                    if (cp.equals(srcPoint)) {
                        continue;
                    }

                    packetOut(cp, eth);
                }
            }

            return;
        }
    }

    /**
     * Handle ARP packets received from the WAN port (AS65000 side).
     * - Block ARP not destined to frr0's WAN IP
     * - Forward ARP replies to frr0
     * - Send proxy ARP replies for ARP requests targeting frr0's WAN IP
     */
    private void handleWanARP(PacketContext context, Ethernet eth) {
        ARP arp = (ARP) eth.getPayload();
        Ip4Address srcIp = Ip4Address.valueOf(arp.getSenderProtocolAddress());
        Ip4Address dstIp = Ip4Address.valueOf(arp.getTargetProtocolAddress());
        MacAddress srcMac = eth.getSourceMAC();
        MacAddress dstMac = eth.getDestinationMAC();

        if (arp.getOpCode() == ARP.OP_REPLY) {
            // Block ARP reply if destination MAC is not frr0's MAC
            if (frr0Mac == null || !dstMac.equals(frr0Mac)) {
                log.debug("Blocking WAN ARP Reply not for frr0 MAC: dstMac={}", dstMac);
                return;
            }

            // Learn WAN peer's MAC
            ipToMacTable.put(srcIp, srcMac);
            log.info("Learned WAN peer MAC: {} -> {}", srcIp, srcMac);

            // Forward ARP reply to frr0 connect point
            if (frr0ConnectPoint != null) {
                log.info("Forwarding WAN ARP Reply from {} to frr0 at {}", srcIp, frr0ConnectPoint);
                packetOut(frr0ConnectPoint, eth);
            }
            return;
        }

        // Block ARP request not destined to frr0's WAN IP
        if (wanLocalIp4 == null || !dstIp.equals(wanLocalIp4)) {
            log.debug("Blocking WAN ARP Request not for frr0: dstIp={}", dstIp);
            return;
        }

        if (arp.getOpCode() == ARP.OP_REQUEST) {
            // AS65000 is asking for frr0's WAN IP MAC - send proxy ARP reply
            log.info("WAN ARP Request for {} from {}. Replying with frr0 MAC {}", dstIp, srcIp, frr0Mac);
            Ethernet arpReply = buildArpReply(dstIp, frr0Mac, srcIp, srcMac);
            packetOut(externalPort, arpReply);
            return;
        }
    }

    /**
     * Handle NDP packets received from the WAN port (AS65000 side).
     * - Block NDP not destined to frr0's WAN IPv6
     * - Forward NDP Neighbor Advertisements to frr0
     * - Send proxy NDP replies for Neighbor Solicitations targeting frr0's WAN IPv6
     */
    private void handleWanNDP(PacketContext context, Ethernet eth) {
        IPv6 ipv6 = (IPv6) eth.getPayload();

        // Verify this is an ICMP6 packet
        if (ipv6.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
            log.debug("Dropping non-ICMP6 IPv6 from WAN port");
            return;
        }

        ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
        byte type = icmp6.getIcmpType();

        // Only handle NDP packets (NS and NA)
        if (type != ICMP6.NEIGHBOR_SOLICITATION && type != ICMP6.NEIGHBOR_ADVERTISEMENT) {
            log.debug("Dropping non-NDP ICMP6 from WAN port: type={}", type);
            return;
        }

        MacAddress srcMac = eth.getSourceMAC();
        MacAddress dstMac = eth.getDestinationMAC();
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());

        // Handle Neighbor Advertisement (response to our NS)
        if (type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
            // Block NA if destination MAC is not frr0's MAC
            if (frr0Mac == null || !dstMac.equals(frr0Mac)) {
                log.debug("Blocking WAN Neighbor Advertisement not for frr0 MAC: dstMac={}", dstMac);
                return;
            }

            // Learn WAN peer's IPv6 and MAC
            ip6ToMacTable.put(srcIp, srcMac);
            log.info("Learned WAN peer IPv6 MAC: {} -> {}", srcIp, srcMac);

            // Forward NA to frr0 connect point
            if (frr0ConnectPoint != null) {
                log.info("Forwarding WAN Neighbor Advertisement to frr0 at {}", frr0ConnectPoint);
                packetOut(frr0ConnectPoint, eth);
            }
            return;
        }

        // Handle Neighbor Solicitation (request from AS65000)
        if (type == ICMP6.NEIGHBOR_SOLICITATION) {
            NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
            byte[] targetBytes = ns.getTargetAddress();
            Ip6Address targetIp = Ip6Address.valueOf(targetBytes);

            // Block NS not destined to frr0's WAN IPv6
            if (wanLocalIp6 == null || !targetIp.equals(wanLocalIp6)) {
                log.debug("Blocking WAN Neighbor Solicitation not for frr0: targetIp={}", targetIp);
                return;
            }

            // AS65000 is asking for frr0's WAN IPv6 MAC - send proxy NDP reply
            log.info("WAN Neighbor Solicitation for {}. Replying with frr0 MAC {}", targetIp, frr0Mac);

            // Learn the WAN peer's IPv6 and MAC from the NS
            ip6ToMacTable.put(srcIp, srcMac);
            log.info("Learned WAN peer IPv6 MAC from NS: {} -> {}", srcIp, srcMac);

            Ethernet ndpReply = NeighborAdvertisement2.buildNdpAdv(targetIp, frr0Mac, eth);
            packetOut(externalPort, ndpReply);
            return;
        }
    }

    private void handleNDP(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();

        // Block ALL NDP from peer VXLAN ports (L3 routing - no NDP needed across VXLAN)
        if (isPeerVxlanPort(srcPoint)) {
            log.debug("Blocked NDP from peer VXLAN port {}", srcPoint);
            return;
        }

        // Handle NDP packets from WAN port separately
        if (externalPort != null && srcPoint.equals(externalPort)) {
            handleWanNDP(context, eth);
            return;
        }

        MacAddress srcMac = eth.getSourceMAC();
        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());

        // Check if this is a DAD (Duplicate Address Detection) packet
        // DAD packets have source IP = :: (unspecified address)
        boolean isDadPacket = srcIp.equals(Ip6Address.valueOf("::"));

        // Only learn IP-MAC mapping if not a DAD packet (source IP is valid)
        if (!isDadPacket) {
            ip6ToMacTable.put(srcIp, srcMac);
        }

        DeviceId deviceId = srcPoint.deviceId();
        PortNumber srcPort = srcPoint.port();

        // Learn MAC-port mapping in bridgeTable (critical for L3 routing)
        if (bridgeTable.get(deviceId) == null) {
            bridgeTable.put(deviceId, new HashMap<>());
        }
        bridgeTable.get(deviceId).put(srcMac, srcPort);

        if (ipv6.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
            return;
        }

        ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
        byte type = icmp6.getIcmpType();

        if (type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
            NeighborAdvertisement2 na = (NeighborAdvertisement2) icmp6.getPayload();
            byte[] targetBytes = na.getTargetAddress();
            Ip6Address targetIp = Ip6Address.valueOf(targetBytes);
            MacAddress cachedDstMac = ip6ToMacTable.asJavaMap().get(targetIp);
            ConnectPoint dstHostPoint = findHostEdgePoint(cachedDstMac);

            if (dstHostPoint != null) {
                packetOut(dstHostPoint, eth);
            }

            return;
        }

        if (type == ICMP6.NEIGHBOR_SOLICITATION) {
            NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
            byte[] targetBytes = ns.getTargetAddress();
            Ip6Address targetIp = Ip6Address.valueOf(targetBytes);

            // For DAD packets, do NOT send proxy reply - just flood to let DAD complete
            if (isDadPacket) {
                log.info("DAD Neighbor Solicitation for {}. Flooding to edge ports.", targetIp);

                Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

                for (ConnectPoint cp : edgePoints) {
                    if (cp.equals(srcPoint)) {
                        continue;
                    }

                    packetOut(cp, eth);
                }
                return;
            }

            // Check if NDP is for our virtual gateway IPv6
            if (virtualGatewayIp6 != null && targetIp.equals(virtualGatewayIp6)) {
                log.info("NDP SOLICITATION for virtual gateway IP {}. Replying with MAC {}",
                        virtualGatewayIp6, virtualGatewayMac);

                Ethernet ndpAdv = NeighborAdvertisement2.buildNdpAdv(targetIp, virtualGatewayMac,
                        context.inPacket().parsed());
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, ndpAdv);
                return;
            }

            MacAddress cachedDstMac = ip6ToMacTable.asJavaMap().get(targetIp);

            if (cachedDstMac != null) {
                // log.info("NDP TABLE HIT. Requested MAC = {}", cachedDstMac);

                Ethernet ndpAdv = NeighborAdvertisement2.buildNdpAdv(targetIp, cachedDstMac, context.inPacket().parsed());
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, ndpAdv);
            } else {
                // log.info("NDP TABLE MISS. Send NDP Solicitation to edge ports");

                Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

                for (ConnectPoint cp : edgePoints) {
                    if (cp.equals(srcPoint)) {
                        continue;
                    }

                    packetOut(cp, eth);
                }
            }

            return;
        }
    }

    /**
     * Handle incoming IPv4 packets from peer VXLAN ports.
     * Only allows traffic destined to local SDN network.
     */
    private void handleIncomingPeerVxlanIPv4(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());

        // Security: Only allow traffic destined to local SDN network
        if (localSdnPrefix == null ||
                !localSdnPrefix.contains(IpAddress.valueOf(dstIp.toString()))) {
            log.warn("Blocked IPv4 from peer VXLAN: dst {} not in local prefix {}", dstIp, localSdnPrefix);
            return;
        }

        log.info("Incoming peer VXLAN IPv4: {} -> {}: dst MAC", srcIp, dstIp);

        // Route to local host - lookup MAC and forward
        MacAddress dstMac = ipToMacTable.asJavaMap().get(dstIp);
        if (dstMac != null) {
            routePacket(context, eth, dstMac);
        } else {
            // Flood to find the host
            log.warn("MAC not found for {} from peer VXLAN, flooding", dstIp);
            flood(context);
        }
    }

    /**
     * Handle incoming IPv6 packets from peer VXLAN ports.
     * Only allows traffic destined to local SDN network.
     */
    private void handleIncomingPeerVxlanIPv6(PacketContext context, Ethernet eth) {
        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());

        // Security: Only allow traffic destined to local SDN network
        if (localSdnPrefix6 == null ||
                !localSdnPrefix6.contains(IpAddress.valueOf(dstIp.toString()))) {
            // log.warn("Blocked IPv6 from peer VXLAN: dst {} not in local prefix {}", dstIp, localSdnPrefix6);
            return;
        }

        log.info("Incoming peer VXLAN IPv6: {} -> {}", srcIp, dstIp);

        // Route to local host - lookup MAC and forward
        MacAddress dstMac = ip6ToMacTable.asJavaMap().get(dstIp);
        if (dstMac != null) {
            routePacket(context, eth, dstMac);
        } else {
            // Flood to find the host
            log.warn("MAC not found for {} from peer VXLAN, flooding", dstIp);
            flood(context);
        }
    }

    /**
     * Route IPv4 packet to peer VXLAN port.
     * Rewrites MAC addresses and sends to the peer VXLAN connect point.
     */
    private void routeToPeerVxlan(PacketContext context, Ethernet eth,
                                   Ip4Address dstIp, ConnectPoint peerCp) {
        Ip4Address srcIp = Ip4Address.valueOf(((IPv4) eth.getPayload()).getSourceAddress());

        // Rewrite MACs: src=virtualGateway, dst=peer's gateway MAC (from config)
        MacAddress peerGatewayMac = getPeerGatewayMac(peerCp);
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(peerGatewayMac);

        log.info("Routing to peer VXLAN: {} -> {} via {} (peer gateway MAC: {})",
                srcIp, dstIp, peerCp, peerGatewayMac);

        // Send packet out to peer VXLAN port
        packetOut(peerCp, routedPkt);
    }

    /**
     * Route IPv6 packet to peer VXLAN port.
     * Rewrites MAC addresses and sends to the peer VXLAN connect point.
     */
    private void routeToPeerVxlanV6(PacketContext context, Ethernet eth,
                                     Ip6Address dstIp, ConnectPoint peerCp) {
        Ip6Address srcIp = Ip6Address.valueOf(((IPv6) eth.getPayload()).getSourceAddress());

        // Rewrite MACs: src=virtualGateway, dst=peer's gateway MAC (from config)
        MacAddress peerGatewayMac = getPeerGatewayMac(peerCp);
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(peerGatewayMac);

        log.info("Routing IPv6 to peer VXLAN: {} -> {} via {} (peer gateway MAC: {})",
                srcIp, dstIp, peerCp, peerGatewayMac);

        // Send packet out to peer VXLAN port
        packetOut(peerCp, routedPkt);
    }

    /**
     * Handle L3 routing for IPv4 packets destined to the virtual gateway.
     * Rewrites MAC addresses and forwards to the appropriate destination.
     */
    private void handleL3RoutingIPv4(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());
        MacAddress srcMac = eth.getSourceMAC();

        log.info("L3 Routing IPv4: {} -> {}", srcIp, dstIp);

        // Learn the source IP-MAC mapping
        ipToMacTable.put(srcIp, srcMac);

        // Check if destination is peer SDN network -> route to peer VXLAN
        ConnectPoint peerVxlanCp = getPeerVxlanForDestination(dstIp);
        if (peerVxlanCp != null) {
            routeToPeerVxlan(context, eth, dstIp, peerVxlanCp);
            return;
        }

        // Query RouteService using longest prefix match
        Optional<ResolvedRoute> routeOpt = routeService.longestPrefixLookup(dstIp);
        IpAddress nextHop = null;
        if (routeOpt.isPresent()) {
            ResolvedRoute route = routeOpt.get();
            nextHop = route.nextHop();
            log.info("L3 IPv4 RouteService HIT: IP {}, Prefix {}, Next-Hop {}",
                    dstIp, route.prefix(), nextHop);
        }

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = null;
        if (nextHop != null) {
            dstMac = ipToMacTable.asJavaMap().get(nextHop.getIp4Address());
            if (dstMac == null) {
                log.warn("L3 IPv4: MAC for next-hop {} not found. Packet may be dropped.", nextHop);
                // Optional: We could trigger an ARP for the next-hop here
            }
        } else {
            // Fallback to original logic if RouteService has no entry
            log.info("L3 IPv4 RouteService MISS: IP {}. Falling back to local table/default route.", dstIp);
            dstMac = ipToMacTable.asJavaMap().get(dstIp);
        }

        if (dstMac != null) {
            // We found a MAC, either for the final destination or the next-hop router
            log.info("L3 IPv4 LOCAL/NEXT-HOP: Found MAC {}. Routing packet.", dstMac);
            routePacket(context, eth, dstMac);
        } else if (frr0Mac != null) {
            // Default route: forward to the pre-configured Quagga/FRR router
            log.info("L3 IPv4 REMOTE: IP {} not in table. Forwarding to default frr0 router (MAC={})", dstIp, frr0Mac);
            routePacket(context, eth, frr0Mac);
        } else {
            // No route and no default, flood as a last resort
            log.warn("L3 IPv4: Cannot route to {}. No route, no MAC, and no default router configured.", dstIp);
            flood(context);
        }
    }

    /**
     * Handle L3 routing for IPv6 packets destined to the virtual gateway.
     * Rewrites MAC addresses and forwards to the appropriate destination.
     */
    private void handleL3RoutingIPv6(PacketContext context, Ethernet eth) {
        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());
        MacAddress srcMac = eth.getSourceMAC();

        log.info("L3 Routing IPv6: {} -> {}", srcIp, dstIp);

        // Learn the source IP-MAC mapping (if not link-local)
        if (!srcIp.isLinkLocal()) {
            ip6ToMacTable.put(srcIp, srcMac);
        }

        // Check if destination is peer SDN network -> route to peer VXLAN
        ConnectPoint peerVxlanCp = getPeerVxlanForDestinationV6(dstIp);
        if (peerVxlanCp != null) {
            routeToPeerVxlanV6(context, eth, dstIp, peerVxlanCp);
            return;
        }

        // Query RouteService using longest prefix match
        Optional<ResolvedRoute> routeOpt = routeService.longestPrefixLookup(dstIp);
        IpAddress nextHop = null;
        if (routeOpt.isPresent()) {
            ResolvedRoute route = routeOpt.get();
            nextHop = route.nextHop();
            log.info("L3 IPv6 RouteService HIT: IP {}, Prefix {}, Next-Hop {}",
                    dstIp, route.prefix(), nextHop);
        }

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = null;
        if (nextHop != null) {
            dstMac = ip6ToMacTable.asJavaMap().get(nextHop.getIp6Address());
            if (dstMac == null) {
                log.warn("L3 IPv6: MAC for next-hop {} not found. Packet may be dropped.", nextHop);
                // Optional: We could trigger an NDP for the next-hop here
            }
        } else {
            // Fallback to original logic if RouteService has no entry
            log.info("L3 IPv6 RouteService MISS: IP {}. Falling back to local table/default route.", dstIp);
            dstMac = ip6ToMacTable.asJavaMap().get(dstIp);
        }

        if (dstMac != null) {
            // We found a MAC, either for the final destination or the next-hop router
            log.info("L3 IPv6 LOCAL/NEXT-HOP: Found MAC {}. Routing packet.", dstMac);
            routePacket(context, eth, dstMac);
        } else if (frr0Mac != null) {
            // Default route: forward to the pre-configured Quagga/FRR router
            log.info("L3 IPv6 REMOTE: IP {} not in table. Forwarding to default frr0 router (MAC={})", dstIp, frr0Mac);
            routePacket(context, eth, frr0Mac);
        } else {
            // No route and no default, flood as a last resort
            log.warn("L3 IPv6: Cannot route to {}. No route, no MAC, and no default router configured.", dstIp);
            flood(context);
        }
    }

    /**
     * Route a packet by rewriting MAC addresses and sending to the destination.
     * Source MAC becomes virtualGatewayMac, destination MAC becomes the target MAC.
     */
    private void routePacket(PacketContext context, Ethernet eth, MacAddress dstMac) {
        // Find the output port for this MAC using HostService or bridgeTable
        ConnectPoint outPoint = findHostEdgePoint(dstMac);

        if (outPoint == null) {
            // Try bridge table - search ALL devices, not just source device
            for (Map.Entry<DeviceId, Map<MacAddress, PortNumber>> entry : bridgeTable.entrySet()) {
                DeviceId deviceId = entry.getKey();
                Map<MacAddress, PortNumber> macTable = entry.getValue();
                PortNumber outPort = macTable.get(dstMac);
                if (outPort != null) {
                    outPoint = new ConnectPoint(deviceId, outPort);
                    break;
                }
            }
        }

        // Create a new Ethernet frame with rewritten MACs
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        if (outPoint == null) {
            // MAC not found in any table, flood the rewritten packet
            log.warn("L3 Routing: Cannot find output port for MAC {}. Flooding rewritten packet.", dstMac);
            floodPacket(context, routedPkt);
            return;
        }

        log.info("L3 Routing: Sending packet to {} via port {}", dstMac, outPoint.port());

        // Send the packet out
        packetOut(outPoint, routedPkt);

        // Install flow rules for future packets (optional but recommended for performance)
        installL3FlowRule(context, eth, dstMac, outPoint.port());
    }

    /**
     * Install a flow rule for L3 routed traffic.
     */
    private void installL3FlowRule(PacketContext context, Ethernet eth, MacAddress dstMac, PortNumber outPort) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthDst(virtualGatewayMac);

        if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(org.onlab.packet.IpPrefix.valueOf(
                            Ip4Address.valueOf(ipv4.getDestinationAddress()), 32));
        } else if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
            IPv6 ipv6 = (IPv6) eth.getPayload();
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(org.onlab.packet.IpPrefix.valueOf(
                            Ip6Address.valueOf(ipv6.getDestinationAddress()), 128));
        }

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualGatewayMac)
                .setEthDst(dstMac)
                .setOutput(outPort)
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(40)  // Higher priority than L2 rules
                .fromApp(appId)
                .makeTemporary(30)
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Installed L3 flow rule for destination IP on device {}", deviceId);
    }

    private void handleLearningBridge(PacketContext context, Ethernet ethPkt) {
        InboundPacket pkt = context.inPacket();

        DeviceId recDevId = pkt.receivedFrom().deviceId();
        PortNumber recPort = pkt.receivedFrom().port();
        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = ethPkt.getDestinationMAC();

        // Receive packet-in from new device, create new table for it
        log.info("Received a packet-in from device `{}`.", recDevId.toString());
        if (bridgeTable.get(recDevId) == null) {
            bridgeTable.put(recDevId, new HashMap<>());
        }

        // Learn source MAC address
        if (bridgeTable.get(recDevId).get(srcMac) == null) {
            log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                    recDevId.toString(), srcMac.toString(), recPort.toString());

            bridgeTable.get(recDevId).put(srcMac, recPort);
        }

        // Forward based on destination MAC
        if (bridgeTable.get(recDevId).get(dstMac) == null) {
            // MAC address not found, flood the packet
            log.info("MAC address `{}` is missed on `{}`. Flood the packet.", dstMac.toString(),
                    recDevId.toString());
            flood(context);

        } else {
            // MAC address found, install flow rule
            log.info("MAC address `{}` is matched on `{}`. Install a flow rule.", dstMac.toString(),
                    recDevId.toString());
            installRule(context, bridgeTable.get(recDevId).get(dstMac));
        }
    }

    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
    }

    /**
     * Flood a rewritten Ethernet packet to all edge ports except the source.
     */
    private void floodPacket(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();
        Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

        for (ConnectPoint cp : edgePoints) {
            if (cp.equals(srcPoint)) {
                continue;
            }
            packetOut(cp, eth);
        }
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void installRule(PacketContext context, PortNumber portNumber) {
        Ethernet inPkt = context.inPacket().parsed();

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC())
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(context.inPacket().receivedFrom().deviceId())
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(30)
                .fromApp(appId)
                .makeTemporary(30) // 30-second timeout
                .build();

        // Apply the flow rule
        flowRuleService.applyFlowRules(flowRule);

        packetOut(context, portNumber);
    }

    /**
     * Install PointToPointIntent for IPv4 forwarding between frr0 and WAN peers.
     * Creates bidirectional intents for BGP traffic with AS65000, AS65340, AS65360.
     */
    private void installWanForwardingIntents() {
        if (wanPeerIp4List.isEmpty() || wanLocalIp4 == null || externalPort == null || frr0ConnectPoint == null) {
            log.info("WAN forwarding intents not installed: missing configuration");
            return;
        }

        // Install outbound intents for each WAN peer (frr0 -> peer)
        for (Ip4Address peerIp : wanPeerIp4List) {
            TrafficSelector toWanSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(peerIp, 32))
                    .build();

            PointToPointIntent toWanIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toWanSelector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(frr0ConnectPoint))
                    .filteredEgressPoint(new FilteredConnectPoint(externalPort))
                    .priority(50000)
                    .build();

            intentService.submit(toWanIntent);
            log.info("Installed WAN intent: frr0 ({}) -> peer {} ({})", frr0ConnectPoint, peerIp, externalPort);
        }

        // Single inbound intent: WAN -> frr0 (traffic to frr0's WAN IP)
        TrafficSelector fromWanSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IpPrefix.valueOf(wanLocalIp4, 32))
                .build();

        PointToPointIntent fromWanIntent = PointToPointIntent.builder()
                .appId(appId)
                .selector(fromWanSelector)
                .treatment(DefaultTrafficTreatment.builder().build())
                .filteredIngressPoint(new FilteredConnectPoint(externalPort))
                .filteredEgressPoint(new FilteredConnectPoint(frr0ConnectPoint))
                .priority(50000)
                .build();

        intentService.submit(fromWanIntent);
        log.info("Installed WAN intent: WAN ({}) -> frr0 ({})", externalPort, frr0ConnectPoint);

        log.info("WAN IPv4 forwarding intents installed for {} peers", wanPeerIp4List.size());

        // Note: IPv6 WAN forwarding is handled by the packet processor
        // We do not install intents for IPv6 WAN traffic because:
        // 1. The frr0ConnectPoint (ovs1) and externalPort (ovs2) are on different switches
        // 2. The veth link between ovs1 and ovs2 is not discovered by ONOS via LLDP
        // 3. Intents fail to compile with "Unable to compile intent" error
        // 4. The packet processor already correctly handles WAN IPv6 traffic using packetOut
        if (!wanPeerIp6List.isEmpty() && wanLocalIp6 != null) {
            log.info("WAN IPv6 peering configured: local={}, peers={}", wanLocalIp6, wanPeerIp6List);
            log.info("WAN IPv6 traffic will be handled by packet processor (no intents)");
        }
    }

    /**
     * Install bidirectional PointToPointIntents for internal IPv6 peer traffic.
     * This enables BGP communication between frr0 and frr1 on the fd63::/64 network.
     */
    private void installInternalPeerForwardingIntents() {
        // TODO: Implement similar intents for IPv4 internal peers if needed
        if (internalV6Peers.isEmpty()) {
            log.info("No internal IPv6 peers configured");
            return;
        }

        if (frr0ConnectPoint == null || frr1ConnectPoint == null) {
            log.warn("Cannot install internal peer intents: frr0ConnectPoint={}, frr1ConnectPoint={}",
                    frr0ConnectPoint, frr1ConnectPoint);
            return;
        }

        for (Ip6Address[] peerPair : internalV6Peers) {
            Ip6Address frr0InternalIp = peerPair[0];  // fd63::1
            Ip6Address frr1InternalIp = peerPair[1];  // fd63::2

            // Intent 1: Traffic to frr0's internal IP (fd63::1)
            TrafficSelector toFrr0Selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(frr0InternalIp, 128))
                    .build();

            PointToPointIntent toFrr0Intent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toFrr0Selector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(frr1ConnectPoint))
                    .filteredEgressPoint(new FilteredConnectPoint(frr0ConnectPoint))
                    .priority(45000)
                    .build();

            intentService.submit(toFrr0Intent);
            log.info("Installed internal peer intent: to {} via {} -> {}",
                    frr0InternalIp, frr1ConnectPoint, frr0ConnectPoint);

            // Intent 2: Traffic to frr1's internal IP (fd63::2)
            TrafficSelector toFrr1Selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(frr1InternalIp, 128))
                    .build();

            PointToPointIntent toFrr1Intent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toFrr1Selector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(frr0ConnectPoint))
                    .filteredEgressPoint(new FilteredConnectPoint(frr1ConnectPoint))
                    .priority(45000)
                    .build();

            intentService.submit(toFrr1Intent);
            log.info("Installed internal peer intent: to {} via {} -> {}",
                    frr1InternalIp, frr0ConnectPoint, frr1ConnectPoint);

            log.info("Internal IPv6 BGP forwarding enabled: {} <-> {}", frr0InternalIp, frr1InternalIp);
        }
    }

}
