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
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
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
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.intf.Interface;
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
    private final ConfigFactory<ApplicationId, VRouterConfig> configFactory = new ConfigFactory<ApplicationId, VRouterConfig>(
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

    // FRR router configuration (for default routing)
    private MacAddress frr0Mac;
    private Ip4Address frr0Ip4;
    private Ip6Address frr0Ip6;

    // WAN Connect Point
    private ConnectPoint externalPort;

    // WAN peering configuration
    private Ip4Address wanLocalIp4; // 192.168.70.35
    private List<Ip4Address> wanPeerIp4List = new ArrayList<>(); // BGP peer IPs (AS65000, AS65340, AS65360)
    private ConnectPoint frr0ConnectPoint;
    private ConnectPoint frr1ConnectPoint;

    // WAN IPv6 peering configuration
    private Ip6Address wanLocalIp6; // fd70::35
    private List<Ip6Address> wanPeerIp6List = new ArrayList<>(); // BGP peer IPv6s
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
    private IpPrefix localTraditionalPrefix;
    private IpPrefix localTraditionalPrefix6;
    private IpPrefix peer1TraditionalPrefix;
    private IpPrefix peer2TraditionalPrefix;
    private IpPrefix peer1TraditionalPrefix6;
    private IpPrefix peer2TraditionalPrefix6;
    private List<String[]> v4Peers;
    private List<String[]> v6Peers;

    private ConsistentMap<Ip4Address, MacAddress> ipToMacTable;
    private ConsistentMap<Ip6Address, MacAddress> ip6ToMacTable;
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();

    private ApplicationId appId;

    private VRouterPacketProcessor processor = new VRouterPacketProcessor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.vrouter");

        configRegistry.addListener(configListener);
        configRegistry.registerConfigFactory(configFactory);

        // Initialize ARP/NDP tables
        ipToMacTable = storageService.<Ip4Address, MacAddress>consistentMapBuilder()
                .withName("ip-mac-table")
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .build();

        ip6ToMacTable = storageService.<Ip6Address, MacAddress>consistentMapBuilder()
                .withName("ipv6-mac-table")
                .withSerializer(Serializer.using(KryoNamespaces.API))
                .build();

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

            // Parse v4-peer to get WAN local, WAN peers, and internal peers
            v4Peers = config.v4Peers();
            if (v4Peers != null && !v4Peers.isEmpty()) {
                installV4PeersIntents();
            }
            // if (v4Peers != null && !v4Peers.isEmpty()) {
            // String[] firstPeer = v4Peers.get(0);
            // wanLocalIp4 = Ip4Address.valueOf(firstPeer[0]);
            // wanPeerIp4List.clear();
            // internalV4Peers.clear();

            // for (String[] peer : v4Peers) {
            // Ip4Address localIp = Ip4Address.valueOf(peer[0]);
            // Ip4Address peerIp = Ip4Address.valueOf(peer[1]);

            // if (localIp.equals(wanLocalIp4)) {
            // wanPeerIp4List.add(peerIp);
            // log.info("Loaded WAN v4 peer: local={}, peer={}", localIp, peerIp);
            // } else {
            // internalV4Peers.add(new Ip4Address[] { localIp, peerIp });
            // log.info("Loaded internal v4 peer: local={}, peer={}", localIp, peerIp);
            // }
            // }
            // }

            // Pre-populate WAN local IP -> frr0 MAC mapping
            if (wanLocalIp4 != null && frr0Mac != null && ipToMacTable != null) {
                ipToMacTable.put(wanLocalIp4, frr0Mac);
                log.info("Pre-populated WAN local IPv4 mapping: {} -> {}", wanLocalIp4, frr0Mac);
            }

            // Parse v6-peer to get WAN IPv6 and internal peer addresses
            v6Peers = config.v6Peers();
            if (v6Peers != null && !v6Peers.isEmpty()) {
                installV6PeersIntents();
            }
            // if (v6Peers != null && !v6Peers.isEmpty()) {
            // String[] firstPeer = v6Peers.get(0);
            // wanLocalIp6 = Ip6Address.valueOf(firstPeer[0]);

            // wanPeerIp6List.clear();
            // internalV6Peers.clear();

            // for (String[] peer : v6Peers) {
            // Ip6Address localIp = Ip6Address.valueOf(peer[0]);
            // Ip6Address peerIp = Ip6Address.valueOf(peer[1]);

            // // Check if this is a WAN peer (same /64 as wanLocalIp6)
            // if (isSameSubnet64(localIp, wanLocalIp6)) {
            // wanPeerIp6List.add(peerIp);
            // log.info("Loaded WAN IPv6 peer: local={}, peer={}", localIp, peerIp);
            // } else {
            // // This is an internal peer
            // internalV6Peers.add(new Ip6Address[] { localIp, peerIp });
            // log.info("Loaded internal IPv6 peering config: local={}, peer={}", localIp,
            // peerIp);
            // }
            // }
            // }

            // Pre-populate WAN local IPv6 -> frr0 MAC mapping
            if (wanLocalIp6 != null && frr0Mac != null && ip6ToMacTable != null) {
                ip6ToMacTable.put(wanLocalIp6, frr0Mac);
                log.info("Pre-populated WAN local IPv6 mapping: {} -> {}", wanLocalIp6, frr0Mac);
            }

            // Pre-populate internal peer IPv6 -> frr0 MAC mapping (for frr0's internal IPs)
            // for (Ip6Address[] peerPair : internalV6Peers) {
            //     Ip6Address localIp = peerPair[0];
            //     if (frr0Mac != null && ip6ToMacTable != null) {
            //         ip6ToMacTable.put(localIp, frr0Mac);
            //         log.info("Pre-populated internal IPv6 mapping: {} -> {}", localIp, frr0Mac);
            //     }
            // }

            installFrrToFpmFlowRules();

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

            // Load local traditional network prefix
            localTraditionalPrefix = config.localTraditionalPrefix();
            localTraditionalPrefix6 = config.localTraditionalPrefix6();
            log.info("Loaded local traditional prefix: {}, IPv6: {}", localTraditionalPrefix, localTraditionalPrefix6);

            // Load peer traditional prefixes
            peer1TraditionalPrefix = config.peer1TraditionalPrefix();
            peer2TraditionalPrefix = config.peer2TraditionalPrefix();
            peer1TraditionalPrefix6 = config.peer1TraditionalPrefix6();
            peer2TraditionalPrefix6 = config.peer2TraditionalPrefix6();
            log.info("Loaded peer traditional prefixes: peer1={}, peer2={}", peer1TraditionalPrefix,
                    peer2TraditionalPrefix);
            log.info("Loaded peer traditional IPv6 prefixes: peer1={}, peer2={}", peer1TraditionalPrefix6,
                    peer2TraditionalPrefix6);

            installVirtualGatewayInterceptRule();
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

    private boolean isPeerVxlanPort(ConnectPoint cp) {
        return (peer1VxlanCp != null && cp.equals(peer1VxlanCp)) ||
                (peer2VxlanCp != null && cp.equals(peer2VxlanCp));
    }

    /**
     * Extract MAC address from IPv6 link-local address using EUI-64 format.
     *
     * EUI-64 embeds MAC in the interface identifier (last 64 bits) with:
     * - ff:fe inserted in the middle of the MAC
     * - 7th bit (U/L bit) of the first byte inverted
     *
     * Example: fe80::b8a7:aeff:fee3:48af → BA:A7:AE:E3:48:AF
     * b8 XOR 02 = ba (invert U/L bit)
     *
     * @param linkLocal IPv6 link-local address
     * @return MAC address extracted from the link-local address
     */
    private MacAddress macFromLinkLocal(Ip6Address linkLocal) {
        byte[] addr = linkLocal.toOctets(); // 16 bytes
        // Interface ID is bytes 8-15 (last 64 bits)
        // EUI-64 format: [8][9][10]:ff:fe:[13][14][15] with bit 7 inverted in byte[8]
        byte[] mac = new byte[6];
        mac[0] = (byte) (addr[8] ^ 0x02); // Invert U/L bit (7th bit)
        mac[1] = addr[9];
        mac[2] = addr[10];
        // Skip addr[11]=0xff, addr[12]=0xfe (EUI-64 insertion)
        mac[3] = addr[13];
        mac[4] = addr[14];
        mac[5] = addr[15];
        return MacAddress.valueOf(mac);
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

            if (eth.getEtherType() == Ethernet.TYPE_ARP) {
                handleARP(context, eth);
                return;
            }

            if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                ConnectPoint srcPoint = context.inPacket().receivedFrom();
                IPv4 ipv4 = (IPv4) eth.getPayload();
                Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
                Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());

                if (isPeerVxlanPort(srcPoint)) {
                    // TODO: Allow only to frr0 and local SDN prefix
                    if (localSdnPrefix == null || !localSdnPrefix.contains(dstIp)) {
                        // log.warn("[Peer VXLAN] Blocked IPv4: src {} -> dst {} (not in local SDN)",
                        // srcIp, dstIp);
                        return;
                    }
                    log.info("[Peer VXLAN] Allowed IPv4: src {} -> dst {}", srcIp, dstIp);
                    // Fall through to normal processing (frr0Mac intercept)
                }

                // Handle IPv4 from WAN port
                if (externalPort != null && srcPoint.equals(externalPort)) {

                    if (wanLocalIp4 != null && dstIp.equals(wanLocalIp4)) {
                        if (frr0ConnectPoint != null) {
                            packetOut(frr0ConnectPoint, eth);
                        }
                        return;
                    }
                    // TODO: Allow to frr0 and to local traditional prefix only
                    if (localTraditionalPrefix != null && localTraditionalPrefix.contains(dstIp)) {
                        log.info("[WAN] Allowing traffic to traditional network: dstIp={}", dstIp);
                        // Fall through to L3 routing
                    } else {
                        // Drop external IPv4 traffic not destined for frr0 or traditional network
                        return;
                    }
                }

                // Handle IPv4 traffic FROM frr0 TO WAN peers (outbound BGP traffic)
                if (frr0ConnectPoint != null && srcPoint.equals(frr0ConnectPoint) && !wanPeerIp4List.isEmpty()) {
                    for (Ip4Address peerIp : wanPeerIp4List) {
                        if (dstIp.equals(peerIp)) {
                            log.info("Forwarding frr0 IPv4 to WAN peer {}: {} -> {}", peerIp, frr0ConnectPoint,
                                    externalPort);
                            packetOut(externalPort, eth);
                            return;
                        }
                    }
                }

                log.info("[DEBUG] IPv4 Packet from {}: srcIP={}, dstIP={}, srcMAC={}, dstMAC={}",
                        srcPoint, srcIp, dstIp, eth.getSourceMAC(), eth.getDestinationMAC());

                // BGP IPv4 are all handled with flow rules
                // All other IPv4 packets to frr0Mac are assumed for gateway routing
                if (frr0Mac != null && eth.getDestinationMAC().equals(frr0Mac)) {
                    // Packets to local SDN prefix -> route to local host
                    if (localSdnPrefix != null && localSdnPrefix.contains(dstIp)) {
                        log.info(
                                "[Gateway] Route Inter-AS IPv4 packet to local subnet: dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIp);
                        routeToLocalSubnet(context, eth);
                        return;
                    } else {
                        // Packets to local traditional prefix -> route via L3 (frr0)
                        log.info(
                                "[Gateway] Route Transit IPv4 packet: dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIp);
                        handleL3RoutingIPv4(context, eth);
                        return;

                    }
                }

                handleByLearningBridge(context, eth);
                return;
            }

            if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
                ConnectPoint srcPoint = context.inPacket().receivedFrom();
                IPv6 ipv6 = (IPv6) eth.getPayload();

                // TODO: Allow only to frr0 and local SDN prefix
                if (isPeerVxlanPort(srcPoint)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
                    Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());
                    // Block if destination not in local SDN prefix
                    if (localSdnPrefix6 == null || !localSdnPrefix6.contains(dstIp)) {
                        return;
                    }
                    log.info("[Peer VXLAN] Allowed IPv6: src {} -> dst {}", srcIp, dstIp);
                }

                // Handle traffic FROM WAN port (inbound)
                if (externalPort != null && srcPoint.equals(externalPort)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

                    // Handle NDP packets from WAN port separately
                    if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                        ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                        byte type = icmp6.getIcmpType();
                        if (type == ICMP6.NEIGHBOR_SOLICITATION || type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                            handleWanNDP(context, eth);
                            return;
                        }
                    }

                    // Allow traffic to frr0's WAN IP
                    if (wanLocalIp6 != null && dstIp.equals(wanLocalIp6)) {
                        if (frr0ConnectPoint != null) {
                            log.info("Forwarding WAN IPv6 to frr0: {} -> {}", dstIp, frr0ConnectPoint);
                            packetOut(frr0ConnectPoint, eth);
                        }
                        return;
                    }

                    // TODO: Allow to frr0 and to local traditional prefix only
                    // Allow traffic to local traditional prefix (return traffic from h3 via WAN)
                    if (localTraditionalPrefix6 != null && localTraditionalPrefix6.contains(dstIp)) {
                        log.info("[WAN] Allowing IPv6 traffic to traditional network: dstIp={}", dstIp);
                        // Fall through to L3 routing (frr0Mac intercept will handle it)
                    } else {
                        // Block other IPv6 traffic from WAN
                        log.debug("Blocking WAN IPv6 not for frr0 or traditional: dstIp={}", dstIp);
                        return;
                    }
                }

                // Handle NDP (Neighbor Solicitation and Advertisement)
                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte type = icmp6.getIcmpType();
                    Ip6Address icmpSrcIp = Ip6Address.valueOf(ipv6.getSourceAddress());
                    Ip6Address icmpDstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

                    log.info("[DEBUG] ICMPv6 from {}: type={}, srcIP={}, dstIP={}, srcMAC={}, dstMAC={}",
                            srcPoint, type, icmpSrcIp, icmpDstIp, eth.getSourceMAC(), eth.getDestinationMAC());

                    if (type == ICMP6.NEIGHBOR_SOLICITATION || type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        handleNDP(context, eth);
                        return;
                    }
                }

                // TODO: There are actually multiple ip6s for frr. Review if any flow will
                // impact this
                Ip6Address dstIpV6 = Ip6Address.valueOf(ipv6.getDestinationAddress());
                if (frr0Mac != null && eth.getDestinationMAC().equals(frr0Mac)) {
                    // Packets to local SDN prefix -> route to local host
                    if (localSdnPrefix6 != null && localSdnPrefix6.contains(dstIpV6)) {
                        log.info(
                                "[Gateway] Handle Inter-AS IPv6 packet to local subnet (for frr0): dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIpV6);
                        routeToLocalSubnetV6(context, eth);
                        return;
                    }

                    // Packets to local traditional prefix -> route via L3 (frr0)
                    if (localTraditionalPrefix6 != null && localTraditionalPrefix6.contains(dstIpV6)) {
                        log.info("[Gateway] Handle Inter-AS IPv6 to external network: dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIpV6);
                        handleL3RoutingIPv6(context, eth);
                        return;
                    }
                }

                handleByLearningBridge(context, eth);
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

    /**
     * Build an ARP REQUEST packet from the virtual gateway to discover a host's
     * MAC.
     */
    private Ethernet buildArpRequest(Ip4Address targetIp) {
        ARP arpRequest = new ARP();
        arpRequest.setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setHardwareAddressLength((byte) MacAddress.MAC_ADDRESS_LENGTH)
                .setProtocolAddressLength((byte) Ip4Address.BYTE_LENGTH)
                .setOpCode(ARP.OP_REQUEST)
                .setSenderHardwareAddress(virtualGatewayMac.toBytes())
                .setSenderProtocolAddress(virtualGatewayIp4.toOctets())
                .setTargetHardwareAddress(MacAddress.ZERO.toBytes())
                .setTargetProtocolAddress(targetIp.toOctets());

        Ethernet ethPkt = new Ethernet();
        ethPkt.setEtherType(Ethernet.TYPE_ARP)
                .setSourceMACAddress(virtualGatewayMac)
                .setDestinationMACAddress(MacAddress.BROADCAST)
                .setVlanID(VlanId.NONE.toShort())
                .setPayload(arpRequest);

        return ethPkt;
    }

    /**
     * Send an ARP request to discover a local host's MAC address.
     * Floods ARP request to all edge ports except peer VXLAN and external ports.
     */
    private void sendArpRequest(Ip4Address targetIp) {
        log.info("[Gateway] Sending ARP request for {} from virtual gateway", targetIp);

        Ethernet arpRequest = buildArpRequest(targetIp);

        Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();
        for (ConnectPoint cp : edgePoints) {
            // Skip peer VXLAN ports - no ARP needed across VXLAN
            if (isPeerVxlanPort(cp)) {
                continue;
            }
            // Skip external WAN port
            if (externalPort != null && cp.equals(externalPort)) {
                continue;
            }
            packetOut(cp, arpRequest);
        }
    }

    /**
     * Build an NDP Neighbor Solicitation packet from the virtual gateway to
     * discover a host's MAC.
     */
    private Ethernet buildNdpSolicitation(Ip6Address targetIp) {
        // Compute solicited-node multicast address: ff02::1:ffXX:XXXX
        byte[] targetBytes = targetIp.toOctets();
        byte[] solicitedNodeAddr = new byte[] {
                (byte) 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, (byte) 0xff,
                targetBytes[13], targetBytes[14], targetBytes[15]
        };

        // Compute solicited-node multicast MAC: 33:33:ff:XX:XX:XX
        byte[] solicitedNodeMac = new byte[] {
                0x33, 0x33, (byte) 0xff,
                targetBytes[13], targetBytes[14], targetBytes[15]
        };

        // Build Neighbor Solicitation
        NeighborSolicitation ns = new NeighborSolicitation();
        ns.setTargetAddress(targetBytes);
        // Add source link-layer address option (type 1)
        ns.addOption(NeighborDiscoveryOptions.TYPE_SOURCE_LL_ADDRESS, virtualGatewayMac.toBytes());

        ICMP6 icmp6 = new ICMP6();
        icmp6.setIcmpType(ICMP6.NEIGHBOR_SOLICITATION);
        icmp6.setIcmpCode((byte) 0);
        icmp6.setPayload(ns);

        IPv6 ipv6 = new IPv6();
        ipv6.setSourceAddress(virtualGatewayIp6.toOctets());
        ipv6.setDestinationAddress(solicitedNodeAddr);
        ipv6.setNextHeader(IPv6.PROTOCOL_ICMP6);
        ipv6.setHopLimit((byte) 255);
        ipv6.setPayload(icmp6);

        Ethernet eth = new Ethernet();
        eth.setEtherType(Ethernet.TYPE_IPV6);
        eth.setSourceMACAddress(virtualGatewayMac);
        eth.setDestinationMACAddress(MacAddress.valueOf(solicitedNodeMac));
        eth.setPayload(ipv6);

        return eth;
    }

    /**
     * Send an NDP Neighbor Solicitation to discover a local host's MAC address.
     * Floods NDP solicitation to all edge ports except peer VXLAN and external
     * ports.
     */
    private void sendNdpSolicitation(Ip6Address targetIp) {
        if (virtualGatewayIp6 == null) {
            log.warn("[Gateway] Cannot send NDP solicitation: virtualGatewayIp6 not configured");
            return;
        }

        log.info("[Gateway] Sending NDP solicitation for {} from virtual gateway", targetIp);

        Ethernet ndpSolicitation = buildNdpSolicitation(targetIp);

        Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();
        for (ConnectPoint cp : edgePoints) {
            // Skip peer VXLAN ports - no NDP needed across VXLAN
            if (isPeerVxlanPort(cp)) {
                continue;
            }
            // Skip external WAN port
            if (externalPort != null && cp.equals(externalPort)) {
                continue;
            }
            packetOut(cp, ndpSolicitation);
        }
    }

    public ConnectPoint findHostEdgePoint(MacAddress dstMac) {
        HostId hostId = HostId.hostId(dstMac, VlanId.NONE);
        Host host = hostService.getHost(hostId);

        if (host == null) {
            return null;
        }

        HostLocation loc = host.location();
        ConnectPoint cp = new ConnectPoint(loc.deviceId(), loc.port());

        // Filter out WAN and peer VXLAN ports - local hosts cannot be located there
        // HostService may incorrectly learn MAC locations from flooded/transit traffic
        if (externalPort != null && cp.equals(externalPort)) {
            log.debug("Ignoring HostService location on WAN port for MAC {}", dstMac);
            return null;
        }
        if (isPeerVxlanPort(cp)) {
            log.debug("Ignoring HostService location on peer VXLAN port for MAC {}", dstMac);
            return null;
        }

        return cp;
    }

    /**
     * Find ConnectPoint for a MAC address by searching all devices in bridgeTable.
     *
     * @param mac the MAC address to look up
     * @return ConnectPoint if found, null otherwise
     */
    private ConnectPoint findConnectPointInBridgeTable(MacAddress mac) {
        for (Map.Entry<DeviceId, Map<MacAddress, PortNumber>> entry : bridgeTable.entrySet()) {
            DeviceId deviceId = entry.getKey();
            Map<MacAddress, PortNumber> macTable = entry.getValue();
            PortNumber outPort = macTable.get(mac);
            if (outPort != null) {
                return new ConnectPoint(deviceId, outPort);
            }
        }
        return null;
    }

    private void handleARP(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();

        // Block ALL ARP from peer VXLAN ports (L3 routing - no ARP needed across VXLAN)
        if (isPeerVxlanPort(srcPoint)) {
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
        log.info("[ARP] Learned sender MAC {} from {} (port {})", srcMac, srcIp, srcPort);
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
                log.info("[ProxyARP] ARP TABLE HIT. Requested MAC = {}", cachedDstMac);

                Ethernet arpPkt = buildArpReply(dstIp, cachedDstMac, srcIp, srcMac);
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, arpPkt);
            } else {
                log.info("[ProxyARP] ARP TABLE MISS: {}. Send request to edge ports", dstIp);

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
            return;
        }

        ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
        byte type = icmp6.getIcmpType();

        // Only handle NDP packets (NS and NA)
        if (type != ICMP6.NEIGHBOR_SOLICITATION && type != ICMP6.NEIGHBOR_ADVERTISEMENT) {
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
            return;
        }

        MacAddress srcMac = eth.getSourceMAC();
        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());

        log.info("[NDP] Packet received from {}: srcIp={}, dstIp={}",
                srcPoint, srcIp, Ip6Address.valueOf(ipv6.getDestinationAddress()));

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
            // Forward NA to the requester (destination of the NA, not the target)
            // NA: srcIP=advertiser, dstIP=requester, targetIP=advertised address
            Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
            MacAddress dstMac = eth.getDestinationMAC();

            // Find requester's location using Ethernet destination MAC
            ConnectPoint dstHostPoint = findHostEdgePoint(dstMac);
            if (dstHostPoint == null) {
                // Try bridge table
                dstHostPoint = findConnectPointInBridgeTable(dstMac);
            }

            log.info("[NDP Advertisement] srcIP={}, dstIP={}, dstMAC={}", srcIp, dstIp, dstMac);

            if (dstHostPoint != null) {
                log.info("Forwarding NDP Advertisement to requester at {}", dstHostPoint);
                packetOut(dstHostPoint, eth);
            } else {
                log.warn("Cannot find requester location for NDP Advertisement: dstMAC={}", dstMac);
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
                log.info("NDP TABLE HIT. Requested MAC = {}", cachedDstMac);

                Ethernet ndpAdv = NeighborAdvertisement2.buildNdpAdv(targetIp, cachedDstMac,
                        context.inPacket().parsed());
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, ndpAdv);
            } else {
                log.info("NDP TABLE MISS for target {}.  NDP Solicitation to edge ports", targetIp);

                Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

                for (ConnectPoint cp : edgePoints) {
                    if (cp.equals(srcPoint)) {
                        continue;
                    }
                    // log.info("NDP Solicitation to edge {}", cp);
                    packetOut(cp, eth);
                }
            }

            return;
        }
    }

    /**
     * Handle packets intercepted by virtual gateway interception rule.
     * These are packets from AS65351 (via frr0) destined to local hosts with:
     * 
     * - dstIP = local host IP (in 172.16.35.0/24, but not frr0's IP)
     */
    private void routeToLocalSubnet(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());
        DeviceId ingressDevice = context.inPacket().receivedFrom().deviceId();

        log.info("[Gateway] Routing packet to local subnet: src {} -> dst {} on device {}",
                srcIp, dstIp, ingressDevice);

        MacAddress dstMac = ipToMacTable.asJavaMap().get(dstIp);

        if (dstMac == null) {
            log.info("[Gateway] MAC not found for {}. Sending ARP request.", dstIp);
            sendArpRequest(dstIp);
            return;
        }

        log.info("[Gateway] MAC found for {} -> {}. Looking for out point.", dstIp, dstMac);

        ConnectPoint outPoint = findHostEdgePoint(dstMac);

        if (outPoint == null) {
            outPoint = findConnectPointInBridgeTable(dstMac);
        }

        if (outPoint == null) {
            log.warn("[Gateway] No output point with MAC {}. Trigger ARP Request.", dstMac);
            sendArpRequest(dstIp);
            return;
        }

        routePacket(context, eth, dstMac, outPoint);
    }

    /**
     * Handle IPv6 packets intercepted by virtual gateway interception rule.
     * - dstMAC = frr0 MAC
     */
    private void routeToLocalSubnetV6(PacketContext context, Ethernet eth) {
        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
        Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());
        DeviceId ingressDevice = context.inPacket().receivedFrom().deviceId();

        log.info("[Gateway] Inter-AS IPv6 packet to local subnet: src {} -> dst {} on device {}",
                srcIp, dstIp, ingressDevice);

        MacAddress dstMac = ip6ToMacTable.asJavaMap().get(dstIp);

        if (dstMac == null) {
            // MAC not found - send NDP solicitation to discover host
            log.info("[Gateway] MAC not found for {}. Sending NDP solicitation.", dstIp);
            sendNdpSolicitation(dstIp);
            return;
        }

        log.info("[Gateway] MAC found for {}: {}. Searching out point.", dstIp, dstMac);

        ConnectPoint outPoint = findHostEdgePoint(dstMac);

        if (outPoint == null) {
            outPoint = findConnectPointInBridgeTable(dstMac);
        }

        if (outPoint == null) {
            log.warn("[Gateway] Cannot find output port for MAC {}. Trigger NDP Solicitation.", dstMac);
            sendNdpSolicitation(dstIp);
            return;
        }

        routePacketV6(context, eth, dstMac, outPoint);
    }

    /**
     * Handle L3 routing for IPv4 packets destined to the virtual gateway.
     * Rewrites MAC addresses and forwards to the appropriate destination.
     */
    private void handleL3RoutingIPv4(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());

        log.info("[Gateway] L3 Routing IPv4: {} -> {}", srcIp, dstIp);

        Optional<ResolvedRoute> routeOpt = routeService.longestPrefixLookup(dstIp);
        IpAddress nextHop = null;
        if (routeOpt.isPresent()) {
            ResolvedRoute route = routeOpt.get();
            nextHop = route.nextHop();
            log.info("[Gateway] L3 IPv4 RouteService HIT: IP {}, Prefix {}, Next-Hop {}",
                    dstIp, route.prefix(), nextHop);
        }

        if (nextHop == null) {
            log.info("[Gateway] L3 IPv4 RouteService MISS: IP {}. Drop the packet.", dstIp);
            return;
        }

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = ipToMacTable.asJavaMap().get(nextHop.getIp4Address());

        if (dstMac == null) {
            log.warn("[Gateway] L3 IPv4: MAC for next-hop {} not found. Forwarding to default frr0 router (MAC={})",
                    nextHop);
            routePacket(context, eth, frr0Mac, frr0ConnectPoint);
            return;
        }

        log.info("[Gateway] L3 IPv4: NEXT-HOP: Found MAC {}. Routing packet.", dstMac);
        ConnectPoint outPoint = findNextHopOutPoint(eth, nextHop);
        if (outPoint == null) {
            log.warn("L3 Routing: Cannot find out interface for nextHop {}. Drop packet.", nextHop);
            return;
        }

        routePacket(context, eth, dstMac, outPoint);
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

        log.info("[Gateway] L3 Routing IPv6: {} -> {}", srcIp, dstIp);

        // Learn the source IP-MAC mapping (if not link-local)
        if (!srcIp.isLinkLocal()) {
            ip6ToMacTable.put(srcIp, srcMac);
        }

        // Query RouteService using longest prefix match
        Optional<ResolvedRoute> routeOpt = routeService.longestPrefixLookup(dstIp);
        IpAddress nextHop = null;
        if (routeOpt.isPresent()) {
            ResolvedRoute route = routeOpt.get();
            nextHop = route.nextHop();
            log.info("[Gateway] L3 IPv6 RouteService HIT: IP {}, Prefix {}, Next-Hop {}",
                    dstIp, route.prefix(), nextHop);
        }

        if (nextHop == null) {
            log.info("[Gateway] L3 IPv6 RouteService MISS: IP {}. Drop the packet.", dstIp);
            return;
        }

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = null;
        Ip6Address nextHopIp6 = nextHop.getIp6Address();

        // Handle link-local next-hops (fe80::) - derive MAC from EUI-64
        if (nextHopIp6.isLinkLocal()) {
            dstMac = macFromLinkLocal(nextHopIp6);
            log.info("[Gateway] L3 IPv6: Next-hop {} is link-local. Derived MAC: {}",
                    nextHopIp6, dstMac);
        } else {
            dstMac = ip6ToMacTable.asJavaMap().get(nextHopIp6);
        }

        if (dstMac == null) {
            log.info("[Gateway] L3 IPv6: Next-hop MAC not found. Forward to default frr0 router (MAC={})",
                    frr0Mac);
            routePacketV6(context, eth, frr0Mac, frr0ConnectPoint);
            return;
        }

        log.info("[Gateway] L3 IPv6: Found NEXT-HOP MAC {}.", dstMac);
        ConnectPoint outPoint = findIp6NextHopOutput(eth, nextHopIp6);

        if (outPoint == null) {
            log.warn("[Gateway] L3 IPv6: Cannot find output interfacce for nextHop {}. Drop packet.", nextHopIp6);
            return;
        }

        routePacketV6(context, eth, dstMac, outPoint);
    }

    private ConnectPoint findNextHopOutPoint(Ethernet eth, IpAddress nextHopIp) {
        ConnectPoint outPoint = null;

        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());

        // Check if destination is in peer traditional networks (route via WAN)
        boolean isPeerTraditional = (peer1TraditionalPrefix != null && peer1TraditionalPrefix.contains(dstIp)) ||
                (peer2TraditionalPrefix != null && peer2TraditionalPrefix.contains(dstIp));

        if (isPeerTraditional) {
            outPoint = externalPort;
            log.info("L3 Routing: To WAN interface for peer traditional dstIP {} -> {}",
                    dstIp, outPoint);
        } else {
            Interface matchingIntf = interfaceService.getMatchingInterface(nextHopIp);
            if (matchingIntf != null) {
                outPoint = matchingIntf.connectPoint();
                log.info("L3 Routing: Found interface for nextHop {} -> {}", nextHopIp, outPoint);
            }
        }

        return outPoint;
    }

    /**
     * Route a packet by rewriting MAC addresses and sending to the destination.
     * Source MAC becomes virtualGatewayMac, destination MAC becomes the target MAC.
     */
    private void routePacket(PacketContext context, Ethernet eth, MacAddress dstMac, ConnectPoint outPoint) {

        if (eth.getEtherType() != Ethernet.TYPE_IPV4) {
            return;
        }

        // Create a new Ethernet frame with rewritten MACs
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        log.info("L3 Routing: Sending packet to {} via port {}/{}", dstMac, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        installL3Forwarding(context, eth, dstMac, outPoint);
    }

    private ConnectPoint findIp6NextHopOutput(Ethernet eth, IpAddress nextHopIp6) {
        ConnectPoint outPoint = null;

        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

        boolean isPeerTraditional = (peer1TraditionalPrefix6 != null && peer1TraditionalPrefix6.contains(dstIp)) ||
                (peer2TraditionalPrefix6 != null && peer2TraditionalPrefix6.contains(dstIp));

        if (isPeerTraditional) {
            outPoint = externalPort;
            log.info("L3 Routing IPv6: To WAN interface for peer traditional dstIP {} -> {}",
                    dstIp, outPoint);
        } else {
            // Use interfaceService to find output port based on next-hop IP
            Interface matchingIntf = interfaceService.getMatchingInterface(nextHopIp6);
            if (matchingIntf != null) {
                outPoint = matchingIntf.connectPoint();
                log.info("L3 Routing IPv6: Found interface '{}' for nextHop {} -> {}",
                        matchingIntf.name(), nextHopIp6, outPoint);
            }
        }

        return outPoint;
    }

    private void routePacketV6(PacketContext context, Ethernet eth, MacAddress dstMac, ConnectPoint outPoint) {
        if (eth.getEtherType() != Ethernet.TYPE_IPV6) {
            return;
        }

        // Create a new Ethernet frame with rewritten MACs
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        log.info("L3 Routing IPv6: Sending packet to {} via port {}/{}", dstMac, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        installL3ForwardingV6(context, eth, dstMac, outPoint);
    }

    private void installL3Forwarding(PacketContext context, Ethernet eth, MacAddress dstMac,
            ConnectPoint outPoint) {
        ConnectPoint ingressCp = context.inPacket().receivedFrom();
        IPv4 ipv4 = (IPv4) eth.getPayload();

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthDst(frr0Mac)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IpPrefix.valueOf(
                        Ip4Address.valueOf(ipv4.getDestinationAddress()), 32));

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualGatewayMac)
                .setEthDst(dstMac)
                .build();

        PointToPointIntent forwardingIntent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selectorBuilder.build())
                .treatment(treatment)
                .filteredIngressPoint(new FilteredConnectPoint(ingressCp))
                .filteredEgressPoint(new FilteredConnectPoint(outPoint))
                .priority(60)
                .build();

        intentService.submit(forwardingIntent);
        log.info("Installed L3 forwarding from {} -> {}", ingressCp, outPoint);
    }

    private void installL3ForwardingV6(PacketContext context, Ethernet eth, MacAddress dstMac,
            ConnectPoint outPoint) {
        ConnectPoint ingressCp = context.inPacket().receivedFrom();
        IPv6 ipv6 = (IPv6) eth.getPayload();

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthDst(frr0Mac)
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchIPv6Dst(IpPrefix.valueOf(
                        Ip6Address.valueOf(ipv6.getDestinationAddress()), 128));

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualGatewayMac)
                .setEthDst(dstMac)
                .build();

        PointToPointIntent forwardingIntent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selectorBuilder.build())
                .treatment(treatment)
                .filteredIngressPoint(new FilteredConnectPoint(ingressCp))
                .filteredEgressPoint(new FilteredConnectPoint(outPoint))
                .priority(60)
                .build();

        intentService.submit(forwardingIntent);
        log.info("Installed L3 forwarding (IPv6) from {} -> {}", ingressCp, outPoint);
    }

    private void handleByLearningBridge(PacketContext context, Ethernet ethPkt) {
        InboundPacket pkt = context.inPacket();

        DeviceId recDevId = pkt.receivedFrom().deviceId();
        PortNumber recPort = pkt.receivedFrom().port();
        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = ethPkt.getDestinationMAC();

        // Receive packet-in from new device, create new table for it
        log.info("[Learning Bridge] Packet-in from device `{}/{}`.", recDevId.toString(),
                recPort.toString());
        log.info("[Learning Bridge] Source MAC: `{}`, Destination MAC: `{}`.", srcMac.toString(),
                dstMac.toString());

        String dstIp = ethPkt.getPayload() instanceof IPv4
                ? Ip4Address.valueOf(((IPv4) ethPkt.getPayload()).getDestinationAddress()).toString()
                : ethPkt.getPayload() instanceof IPv6
                        ? Ip6Address.valueOf(((IPv6) ethPkt.getPayload()).getDestinationAddress()).toString()
                        : "N/A";
        String srcIp = ethPkt.getPayload() instanceof IPv4
                ? Ip4Address.valueOf(((IPv4) ethPkt.getPayload()).getSourceAddress()).toString()
                : ethPkt.getPayload() instanceof IPv6
                        ? Ip6Address.valueOf(((IPv6) ethPkt.getPayload()).getSourceAddress()).toString()
                        : "N/A";

        log.info("[Learning Bridge] DST IP: `{}`, SRC IP: `{}`.", dstIp, srcIp);

        if (bridgeTable.get(recDevId) == null) {
            bridgeTable.put(recDevId, new HashMap<>());
        }

        // Learn source MAC address
        if (bridgeTable.get(recDevId).get(srcMac) == null) {
            // log.info("[Learning Bridge] New entry to device `{}`. MAC: `{}` => Port:
            // `{}`.",
            // recDevId.toString(), srcMac.toString(), recPort.toString());

            bridgeTable.get(recDevId).put(srcMac, recPort);
        }

        // Forward based on destination MAC
        if (bridgeTable.get(recDevId).get(dstMac) == null) {
            // log.info("[Learning Bridge] MAC address `{}` MISS on `{}/{}`. Flood the
            // packet.", dstMac.toString(),
            // recDevId.toString(), recPort.toString());
            flood(context);

        } else {
            // log.info("[Learning Bridge] MAC address `{}` MATCH on `{}/{}`. Install a flow
            // rule.",
            // dstMac.toString(),
            // recDevId.toString(), recPort.toString());
            installL2Rule(context, bridgeTable.get(recDevId).get(dstMac));
        }
    }

    private void flood(PacketContext context) {
        packetOut(context, PortNumber.FLOOD);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void installL2Rule(PacketContext context, PortNumber portNumber) {
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

    private void installFrrToFpmFlowRules() {
        // frr -> onos fpm (port 2620) flow rule
        IpPrefix onosIp4 = IpPrefix.valueOf("192.168.100.2/32");
        IpPrefix frrIp4 = IpPrefix.valueOf("192.168.100.3/32");
        TpPort fpmPort = TpPort.tpPort(2620);
        DeviceId ovs1Id = frr0ConnectPoint.deviceId();
        PortNumber onosPort = ConnectPoint.deviceConnectPoint("of:0000000000000001/3").port();

        TrafficSelector fpmSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(frrIp4)
                .matchIPDst(onosIp4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchTcpDst(fpmPort)
                .build();

        // Output should be the "onos-port" (data plane) and not controller
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(onosPort)
                .build();

        ForwardingObjective frrToFpmFwd = DefaultForwardingObjective.builder()
                .withSelector(fpmSelector)
                .withTreatment(treatment)
                .withPriority(50000) // High priority
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();

        flowObjectiveService.forward(ovs1Id, frrToFpmFwd);

        // Onos -> frr flow rule

        TrafficSelector reverseSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(onosIp4)
                .matchIPDst(frrIp4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .build();

        TrafficTreatment outputFrrTreatment = DefaultTrafficTreatment.builder()
                .setOutput(frr0ConnectPoint.port())
                .build();

        ForwardingObjective onosToFrrFwd = DefaultForwardingObjective.builder()
                .withSelector(reverseSelector)
                .withTreatment(outputFrrTreatment)
                .withPriority(50000)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makePermanent()
                .add();

        flowObjectiveService.forward(frr0ConnectPoint.deviceId(), onosToFrrFwd);
    }

    /**
     * Install PointToPointIntents for IPv4 BGP peers exchange.
     * Uses interfaceService to dynamically determine connect points based on peer
     * IPs:
     * AS65xx0 <-> (AS65yy0 / AS65zz0) through peer VXLAN interface
     * AS65xx0 <-> AS65000 through WAN interface
     * AS65xx0 <-> AS65xx1 through frr1 interface
     */
    private void installV4PeersIntents() {
        if (v4Peers == null || v4Peers.isEmpty()) {
            log.info("No v4-peers configured for intent installation");
            return;
        }

        if (frr0ConnectPoint == null) {
            log.warn("Cannot install v4 peer intents: frr0ConnectPoint not configured");
            return;
        }

        log.info("Available interfaces from InterfaceService:");
        for (Interface intf : interfaceService.getInterfaces()) {
            log.info("  Interface: {} at {} with IPs: {}", intf.name(), intf.connectPoint(), intf.ipAddressesList());
        }
        int installedCount = 0;
        for (String[] peer : v4Peers) {
            Ip4Address localIp = Ip4Address.valueOf(peer[0]);
            Ip4Address peerIp = Ip4Address.valueOf(peer[1]);

            // Find connect points using interfaceService
            Interface localIntf = interfaceService.getMatchingInterface(localIp);
            Interface peerIntf = interfaceService.getMatchingInterface(peerIp);

            log.info("v4-peer lookup: local={} (intf={}), peer={} (intf={})", localIp,
                    localIntf != null ? localIntf.name() : "null", peerIp, peerIntf != null ? peerIntf.name() : "null");

            // Determine connect points - fallback to frr0ConnectPoint for local IPs
            ConnectPoint localCp = (localIntf != null) ? localIntf.connectPoint() : frr0ConnectPoint;
            ConnectPoint peerCp = (peerIntf != null) ? peerIntf.connectPoint() : null;

            if (peerCp == null) {
                log.warn("No interface found for peer IP {}, skipping", peerIp);
                continue;
            }

            // Intent 1: Traffic to peer IP (local -> peer)
            TrafficSelector toPeerSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(peerIp, 32))
                    .build();

            PointToPointIntent toPeerIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toPeerSelector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(localCp))
                    .filteredEgressPoint(new FilteredConnectPoint(peerCp))
                    .priority(50000)
                    .build();

            intentService.submit(toPeerIntent);
            log.info("Installed v4-peer intent: to {} via {} -> {}", peerIp, localCp, peerCp);

            // Intent 2: Traffic to local IP (peer -> local)
            TrafficSelector toLocalSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(localIp, 32))
                    .build();

            PointToPointIntent toLocalIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toLocalSelector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(peerCp))
                    .filteredEgressPoint(new FilteredConnectPoint(localCp))
                    .priority(50000)
                    .build();

            intentService.submit(toLocalIntent);
            log.info("Installed v4-peer intent: to {} via {} -> {}", localIp, peerCp, localCp);

            installedCount++;
        }

        log.info("Installed {} bidirectional v4-peer intent pairs", installedCount);
    }

    /**
     * Install PointToPointIntents for IPv4 BGP peers exchange.
     * Uses interfaceService to dynamically determine connect points based on peer
     * IPs:
     * AS65xx0 <-> (AS65yy0 / AS65zz0) through peer VXLAN interface
     * AS65xx0 <-> AS65000 through WAN interface
     * AS65xx0 <-> AS65xx1 through frr1 interface
     */
    private void installV6PeersIntents() {
        if (v6Peers == null || v6Peers.isEmpty()) {
            log.info("No v6-peers configured for intent installation");
            return;
        }

        if (frr0ConnectPoint == null) {
            log.warn("Cannot install v6 peer intents: frr0ConnectPoint not configured");
            return;
        }

        log.info("Available interfaces from InterfaceService:");
        for (Interface intf : interfaceService.getInterfaces()) {
            log.info("  Interface: {} at {} with IPs: {}", intf.name(), intf.connectPoint(), intf.ipAddressesList());
        }
        int installedCount = 0;
        for (String[] peer : v6Peers) {
            Ip6Address localIp = Ip6Address.valueOf(peer[0]);
            Ip6Address peerIp = Ip6Address.valueOf(peer[1]);

            // Find connect points using interfaceService
            Interface localIntf = interfaceService.getMatchingInterface(localIp);
            Interface peerIntf = interfaceService.getMatchingInterface(peerIp);

            log.info("v6-peer lookup: local={} (intf={}), peer={} (intf={})", localIp,
                    localIntf != null ? localIntf.name() : "null", peerIp, peerIntf != null ? peerIntf.name() : "null");

            // Determine connect points - fallback to frr0ConnectPoint for local IPs
            ConnectPoint localCp = (localIntf != null) ? localIntf.connectPoint() : frr0ConnectPoint;
            ConnectPoint peerCp = (peerIntf != null) ? peerIntf.connectPoint() : null;

            if (peerCp == null) {
                log.warn("No interface found for peer IP {}, skipping", peerIp);
                continue;
            }

            // Intent 1: Traffic to peer IP (local -> peer)
            TrafficSelector toPeerSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(peerIp, 128))
                    .build();

            PointToPointIntent toPeerIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toPeerSelector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(localCp))
                    .filteredEgressPoint(new FilteredConnectPoint(peerCp))
                    .priority(50000)
                    .build();

            intentService.submit(toPeerIntent);
            log.info("Installed v6-peer intent: to {} via {} -> {}", peerIp, localCp, peerCp);

            // Intent 2: Traffic to local IP (peer -> local)
            TrafficSelector toLocalSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(localIp, 128))
                    .build();

            PointToPointIntent toLocalIntent = PointToPointIntent.builder()
                    .appId(appId)
                    .selector(toLocalSelector)
                    .treatment(DefaultTrafficTreatment.builder().build())
                    .filteredIngressPoint(new FilteredConnectPoint(peerCp))
                    .filteredEgressPoint(new FilteredConnectPoint(localCp))
                    .priority(50000)
                    .build();

            intentService.submit(toLocalIntent);
            log.info("Installed v6-peer intent: to {} via {} -> {}", localIp, peerCp, localCp);

            installedCount++;
        }

        log.info("Installed {} bidirectional v6-peer intent pairs", installedCount);
    }

    /**
     * Install flow rule to intercept packets where:
     * - dstMAC = frr0 MAC
     * 
     * BGP peering packets (dstIP = frr0 IPs) forwarded by flow rules and should not
     * be intercepted.
     */
    private void installVirtualGatewayInterceptRule() {
        if (frr0Mac == null) {
            log.warn("Cannot install virtual gateway intercept rule: frr0Mac is null");
            return;
        }

        // Treatment: Send to controller for virtual gateway processing
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER)
                .build();

        // IPv4 selector: match dstMAC = frr0 MAC
        TrafficSelector selectorV4 = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchEthDst(frr0Mac)
                .build();

        // IPv6 selector: match dstMAC = frr0 MAC
        TrafficSelector selectorV6 = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchEthDst(frr0Mac)
                .build();

        // Install on all devices
        for (Device device : deviceService.getDevices()) {
            DeviceId deviceId = device.id();

            FlowRule flowRuleV4 = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV4)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            FlowRule flowRuleV6 = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV6)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(flowRuleV4, flowRuleV6);
            log.info("Installed virtual gateway intercept rules on device {} for dstMAC={}",
                    deviceId, frr0Mac);
        }
    }
}
