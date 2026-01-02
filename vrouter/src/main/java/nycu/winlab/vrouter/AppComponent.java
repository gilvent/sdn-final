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
    private List<Ip4Address[]> internalV4Peers = new ArrayList<>();

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
            List<String[]> v4Peers = config.v4Peers();
            if (v4Peers != null && !v4Peers.isEmpty()) {
                String[] firstPeer = v4Peers.get(0);
                wanLocalIp4 = Ip4Address.valueOf(firstPeer[0]);
                wanPeerIp4List.clear();
                internalV4Peers.clear();

                for (String[] peer : v4Peers) {
                    Ip4Address localIp = Ip4Address.valueOf(peer[0]);
                    Ip4Address peerIp = Ip4Address.valueOf(peer[1]);

                    if (localIp.equals(wanLocalIp4)) {
                        wanPeerIp4List.add(peerIp);
                        log.info("Loaded WAN v4 peer: local={}, peer={}", localIp, peerIp);
                    } else {
                        internalV4Peers.add(new Ip4Address[] { localIp, peerIp });
                        log.info("Loaded internal v4 peer: local={}, peer={}", localIp, peerIp);
                    }
                }
            }

            // // Pre-populate frr0 IP-MAC mappings for L3 routing
            // if (frr0Ip4 != null && frr0Mac != null && ipToMacTable != null) {
            // ipToMacTable.put(frr0Ip4, frr0Mac);
            // log.info("Pre-populated frr0 IPv4 mapping: {} -> {}", frr0Ip4, frr0Mac);
            // }
            // if (frr0Ip6 != null && frr0Mac != null && ip6ToMacTable != null) {
            // ip6ToMacTable.put(frr0Ip6, frr0Mac);
            // log.info("Pre-populated frr0 IPv6 mapping: {} -> {}", frr0Ip6, frr0Mac);
            // }

            // Pre-populate WAN local IP -> frr0 MAC mapping
            if (wanLocalIp4 != null && frr0Mac != null && ipToMacTable != null) {
                ipToMacTable.put(wanLocalIp4, frr0Mac);
                log.info("Pre-populated WAN local IPv4 mapping: {} -> {}", wanLocalIp4, frr0Mac);
            }

            // Parse v6-peer to get WAN IPv6 and internal peer addresses
            List<String[]> v6Peers = config.v6Peers();
            if (v6Peers != null && !v6Peers.isEmpty()) {
                String[] firstPeer = v6Peers.get(0);
                wanLocalIp6 = Ip6Address.valueOf(firstPeer[0]);

                wanPeerIp6List.clear();
                internalV6Peers.clear();

                for (String[] peer : v6Peers) {
                    Ip6Address localIp = Ip6Address.valueOf(peer[0]);
                    Ip6Address peerIp = Ip6Address.valueOf(peer[1]);

                    // Check if this is a WAN peer (same /64 as wanLocalIp6)
                    if (isSameSubnet64(localIp, wanLocalIp6)) {
                        wanPeerIp6List.add(peerIp);
                        log.info("Loaded WAN IPv6 peer: local={}, peer={}", localIp, peerIp);
                    } else {
                        // This is an internal peer
                        internalV6Peers.add(new Ip6Address[] { localIp, peerIp });
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

            installWanForwardingIntents();

            // Internal peer forwarding (IPv6)
            installInternalPeerForwardingIntents();

            // Internal peer forwarding flow rules (IPv4)
            installInternalPeerForwardingFlowRules();

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
     * Get the peer VXLAN connect point for a destination IP.
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

                // Check for intercepted packets: dstMAC = frr0 MAC, dstIP in local subnet (but
                // not frr0's IP)
                if (frr0Mac != null && eth.getDestinationMAC().equals(frr0Mac) &&
                        
                        frr0Ip4 != null && !dstIp.equals(frr0Ip4)) {
                    
                    
                    if (localSdnPrefix != null && localSdnPrefix.contains(dstIp)) {
                        log.info("[Gateway] Intercept Inter-AS packet to local: dstMAC={}, dstIP={}",
                            eth.getDestinationMAC(), dstIp);
                        gatewayToLocalHost(context, eth);
                    } else {
                        log.info("[Gateway] Intercept Inter-AS traffic IPv4: dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIp);
                        handleL3RoutingIPv4(context, eth);
                    }

                    return;
                }

                // Check if this is L3 routing (destination is our virtual gateway MAC)
                if (virtualGatewayMac != null && eth.getDestinationMAC().equals(virtualGatewayMac)) {
                    handleL3RoutingIPv4(context, eth);
                    return;
                }

                forwardByLearningBridge(context, eth);
                return;
            }

            if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
                ConnectPoint srcPoint = context.inPacket().receivedFrom();
                IPv6 ipv6 = (IPv6) eth.getPayload();

                if (isPeerVxlanPort(srcPoint)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
                    Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());
                    // Block if destination not in local SDN prefix
                    if (localSdnPrefix6 == null || !localSdnPrefix6.contains(dstIp)) {
                        return;
                    }
                    log.info("[Peer VXLAN] Allowed IPv6: src {} -> dst {}", srcIp, dstIp);
                    // Fall through to normal processing (frr0Mac intercept)
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

                    // Allow traffic to frr0's WAN IP
                    if (wanLocalIp6 != null && dstIp.equals(wanLocalIp6)) {
                        if (frr0ConnectPoint != null) {
                            log.info("Forwarding WAN IPv6 to frr0: {} -> {}", dstIp, frr0ConnectPoint);
                            packetOut(frr0ConnectPoint, eth);
                        }
                        return;
                    }

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

                // Handle traffic TO WAN port (outbound from frr0)
                if (!wanPeerIp6List.isEmpty() && frr0ConnectPoint != null && srcPoint.equals(frr0ConnectPoint)) {
                    Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

                    // Forward traffic destined to any WAN peer to external port
                    for (Ip6Address peerIp : wanPeerIp6List) {
                        if (dstIp.equals(peerIp)) {
                            log.info("Forwarding frr0 IPv6 to WAN peer {}: {} -> {}", peerIp, frr0ConnectPoint,
                                    externalPort);
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

                // Check for intercepted IPv6 packets: dstMAC = frr0 MAC (but not frr0's IP)
                Ip6Address dstIpV6 = Ip6Address.valueOf(ipv6.getDestinationAddress());
                if (frr0Mac != null && eth.getDestinationMAC().equals(frr0Mac) &&
                        frr0Ip6 != null && !dstIpV6.equals(frr0Ip6)) {

                    // Packets to local SDN prefix -> route to local host
                    if (localSdnPrefix6 != null && localSdnPrefix6.contains(dstIpV6)) {
                        log.info(
                                "[Gateway] Intercept Inter-AS IPv6 packet to local host (for frr0): dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIpV6);
                        gatewayToLocalHostV6(context, eth);
                        return;
                    }

                    // Packets to local traditional prefix -> route via L3 (frr0)
                    if (localTraditionalPrefix6 != null && localTraditionalPrefix6.contains(dstIpV6)) {
                        log.info("[Gateway] Intercept Peer-to-Traditional IPv6: dstMAC={}, dstIP={}",
                                eth.getDestinationMAC(), dstIpV6);
                        handleL3RoutingIPv6(context, eth);
                        return;
                    }
                }

                // Check if this is L3 routing (destination is our virtual gateway MAC)
                if (virtualGatewayMac != null && eth.getDestinationMAC().equals(virtualGatewayMac)) {
                    handleL3RoutingIPv6(context, eth);
                    return;
                }

                // forwardByLearningBridge(context, eth);
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
            // Deserialize with custom class to avoid ClassCastException
            // (ONOS returns built-in NeighborAdvertisement, not our custom class)
            try {
                byte[] naBytes = icmp6.getPayload().serialize();
                NeighborAdvertisement2 na = NeighborAdvertisement2.deserializer()
                        .deserialize(naBytes, 0, naBytes.length);
                byte[] targetBytes = na.getTargetAddress();
                Ip6Address targetIp = Ip6Address.valueOf(targetBytes);
                MacAddress cachedDstMac = ip6ToMacTable.asJavaMap().get(targetIp);
                ConnectPoint dstHostPoint = findHostEdgePoint(cachedDstMac);

                if (dstHostPoint != null) {
                    packetOut(dstHostPoint, eth);
                }
            } catch (Exception e) {
                log.warn("Failed to deserialize Neighbor Advertisement: {}", e.getMessage());
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

                Ethernet ndpAdv = NeighborAdvertisement2.buildNdpAdv(targetIp, cachedDstMac,
                        context.inPacket().parsed());
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
     * Handle packets intercepted by virtual gateway interception rule.
     * These are packets from AS65351 (via frr0) destined to local hosts with:
     * - dstMAC = frr0 MAC
     * - dstIP = local host IP (in 172.16.35.0/24, but not frr0's IP)
     */
    private void gatewayToLocalHost(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());
        DeviceId ingressDevice = context.inPacket().receivedFrom().deviceId();

        log.info("[Gateway] Inter-AS packet to local subnet: src {} -> dst {} on device {}",
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
            // Try bridge table - search all devices
            outPoint = findConnectPointInBridgeTable(dstMac);
        }

        if (outPoint == null) {
            log.warn("[Gateway] Cannot find output port for MAC {}. Trigger ARP Request.", dstMac);
            sendArpRequest(dstIp);
            return;
        }

        // Rewrite MAC addresses and forward
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        log.info("[Gateway] Routing to local host {} via port {}/{}",
                dstIp, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        // Install per-host flow rule for subsequent packets
        installFrr0ToLocalHostFlowRule(context, dstIp, dstMac, outPoint);

    }

    /**
     * Handle IPv6 packets intercepted by virtual gateway interception rule.
     * These are packets from AS65351 (via frr0) destined to local hosts with:
     * - dstMAC = frr0 MAC
     * - dstIP = local host IPv6 (in local SDN prefix, but not frr0's IP)
     */
    private void gatewayToLocalHostV6(PacketContext context, Ethernet eth) {
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

        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        log.info("[Gateway] Routing IPv6 to local host {} via port {}/{}",
                dstIp, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        installFrr0ToLocalHostFlowRuleV6(context, dstIp, dstMac, outPoint);

    }

    /**
     * Route IPv6 packet to peer VXLAN port.
     * Uses RouteService to find next-hop and lookup MAC from ip6ToMacTable.
     * Note: IPv6 will be updated in a future iteration.
     */
    private void routeToPeerVxlanV6(PacketContext context, Ethernet eth,
            MacAddress peerFrr0Mac, ConnectPoint peerCp) {
        Ip6Address srcIp = Ip6Address.valueOf(((IPv6) eth.getPayload()).getSourceAddress());
        Ip6Address dstIp = Ip6Address.valueOf(((IPv6) eth.getPayload()).getDestinationAddress());

        if (peerFrr0Mac == null) {
            log.warn("[Peer VXLAN IPv6] Cannot route to {}: no MAC for next-hop", dstIp);
            return;
        }

        // Rewrite MACs: src=virtualGateway, dst=peer's frr0 MAC
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(peerFrr0Mac);

        log.info("[Peer VXLAN IPv6] Forwarding: {} -> {} via {} (dstMAC: {})",
                srcIp, dstIp, peerCp, peerFrr0Mac);

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

        log.info("[Gateway] L3 Routing IPv4: {} -> {}", srcIp, dstIp);

        // Query RouteService using longest prefix match
        Optional<ResolvedRoute> routeOpt = routeService.longestPrefixLookup(dstIp);
        IpAddress nextHop = null;
        if (routeOpt.isPresent()) {
            ResolvedRoute route = routeOpt.get();
            nextHop = route.nextHop();
            log.info("[Gateway] L3 IPv4 RouteService HIT: IP {}, Prefix {}, Next-Hop {}",
                    dstIp, route.prefix(), nextHop);
        }

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = null;
        if (nextHop != null) {
            dstMac = ipToMacTable.asJavaMap().get(nextHop.getIp4Address());
            if (dstMac == null) {
                log.warn("[Gateway] L3 IPv4: MAC for next-hop {} not found.", nextHop);
            }
        } else {
            log.info("[Gateway] L3 IPv4 RouteService MISS: IP {}.", dstIp);
            // TODO Remove if not used
            // dstMac = ipToMacTable.asJavaMap().get(dstIp);
        }

        if (dstMac != null) {
            log.info("[Gateway] L3 IPv4 LOCAL/NEXT-HOP: Found MAC {}. Routing packet.", dstMac);
            routePacket(context, eth, nextHop, dstMac);
        } else if (frr0Mac != null) {
            log.info("[Gateway] L3 IPv4 REMOTE: IP {} not in table. Forwarding to default frr0 router (MAC={})", dstIp,
                    frr0Mac);
            routePacket(context, eth, nextHop, frr0Mac);
        } else {
            log.warn("[Gateway] L3 IPv4: Cannot route to {}. Dropping the packet.",
                    dstIp);
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

        // Determine the destination MAC based on the next hop
        MacAddress dstMac = null;
        if (nextHop != null) {
            Ip6Address nextHopIp6 = nextHop.getIp6Address();

            dstMac = ip6ToMacTable.asJavaMap().get(nextHopIp6);
            if (dstMac == null) {
                log.warn("[Gateway] L3 IPv6: MAC for next-hop {} not found.", nextHop);
            }

            // Handle link-local next-hops (fe80::) - derive MAC from EUI-64 and route
            // directly
            if (nextHopIp6.isLinkLocal()) {
                dstMac = macFromLinkLocal(nextHopIp6);
                log.info("[Gateway] L3 IPv6: Next-hop {} is link-local. Derived MAC: {}",
                        nextHopIp6, dstMac);
            }

        } else {
            // Fallback to original logic if RouteService has no entry
            log.info("[Gateway] L3 IPv6 RouteService MISS: IP {}. Falling back to local table/default route.", dstIp);
            dstMac = ip6ToMacTable.asJavaMap().get(dstIp);
        }

        if (dstMac != null) {
            // Check if destination is peer SDN network -> route to peer VXLAN
            ConnectPoint peerVxlanCp = getPeerVxlanForDestinationV6(dstIp);
            if (peerVxlanCp != null) {
                routeToPeerVxlanV6(context, eth, dstMac, peerVxlanCp);
                return;
            }

            // We found a MAC, either for the final destination or the next-hop router
            log.info("[Gateway] L3 IPv6 LOCAL/NEXT-HOP: Found MAC {}. Routing packet.", dstMac);
            routePacketV6(context, eth, nextHop, dstMac);
        } else if (frr0Mac != null) {
            // Default route: forward to the pre-configured Quagga/FRR router
            log.info("[Gateway] L3 IPv6 REMOTE: IP {} not in table. Forwarding to default frr0 router (MAC={})", dstIp,
                    frr0Mac);
            routePacketV6(context, eth, frr0Ip6, frr0Mac);
        } else {
            // No route and no default, flood as a last resort
            log.warn("[Gateway] L3 IPv6: Cannot route to {}. No route, no MAC, and no default router configured.",
                    dstIp);
            flood(context);
        }
    }

    /**
     * Route a packet by rewriting MAC addresses and sending to the destination.
     * Source MAC becomes virtualGatewayMac, destination MAC becomes the target MAC.
     */
    private void routePacket(PacketContext context, Ethernet eth, IpAddress nextHopIp, MacAddress dstMac) {
        ConnectPoint outPoint = null;

        if (nextHopIp == null) {
            log.info("L3 Routing: No nextHop. Drop.",
                    dstMac, dstMac);
            return;
        }

        if (eth.getEtherType() != Ethernet.TYPE_IPV4) {
            return;
        }

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
                log.info("L3 Routing: Found interface {} for nextHop {} -> {}",
                        dstMac, nextHopIp, outPoint);
            }
        }

        // Create a new Ethernet frame with rewritten MACs
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        if (outPoint == null) {
            log.warn("L3 Routing: Cannot find out interface for nextHop {}. Drop packet.", nextHopIp);
            return;
        }

        log.info("L3 Routing: Sending packet to {} via port {}/{}", dstMac, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        installL3FlowRule(context, eth, dstMac, outPoint.port(), outPoint);
    }

    private void routePacketV6(PacketContext context, Ethernet eth, IpAddress nextHopIp, MacAddress dstMac) {
        ConnectPoint outPoint = null;

        if (nextHopIp == null) {
            log.info("L3 Routing IPv6: No nextHop. Drop.");
            return;
        }

        if (eth.getEtherType() != Ethernet.TYPE_IPV6) {
            return;
        }

        IPv6 ipv6 = (IPv6) eth.getPayload();
        Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());

        // Check if destination is in peer traditional networks (route via WAN)
        boolean isPeerTraditional = (peer1TraditionalPrefix6 != null && peer1TraditionalPrefix6.contains(dstIp)) ||
                (peer2TraditionalPrefix6 != null && peer2TraditionalPrefix6.contains(dstIp));

        if (isPeerTraditional) {
            outPoint = externalPort;
            log.info("L3 Routing IPv6: To WAN interface for peer traditional dstIP {} -> {}",
                    dstIp, outPoint);
        } else {
            // Use interfaceService to find output port based on next-hop IP
            Interface matchingIntf = interfaceService.getMatchingInterface(nextHopIp);
            if (matchingIntf != null) {
                outPoint = matchingIntf.connectPoint();
                log.info("L3 Routing IPv6: Found interface {} for nextHop {} -> {}",
                        matchingIntf.name(), nextHopIp, outPoint);
            }
        }

        // Create a new Ethernet frame with rewritten MACs
        Ethernet routedPkt = eth.duplicate();
        routedPkt.setSourceMACAddress(virtualGatewayMac);
        routedPkt.setDestinationMACAddress(dstMac);

        if (outPoint == null) {
            log.warn("L3 Routing IPv6: Cannot find interface for nextHop {}. Drop packet.", nextHopIp);
            return;
        }

        log.info("L3 Routing IPv6: Sending packet to {} via port {}/{}", dstMac, outPoint.deviceId(), outPoint.port());

        packetOut(outPoint, routedPkt);

        installL3FlowRule(context, eth, dstMac, outPoint.port(), outPoint);
    }

    private void installL3FlowRule(PacketContext context, Ethernet eth, MacAddress dstMac, PortNumber outPort,
            ConnectPoint outPoint) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

        if (!deviceId.equals(outPoint.deviceId())) {
            return;
        }

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
                .withPriority(40) // Higher priority than L2 rules
                .fromApp(appId)
                .makeTemporary(30)
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Installed L3 flow rule for destination IP on device {}", deviceId);
    }

    private void forwardByLearningBridge(PacketContext context, Ethernet ethPkt) {
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
            // MAC address not found, flood the packet
            // log.info("[Learning Bridge] MAC address `{}` MISS on `{}/{}`. Flood the
            // packet.", dstMac.toString(),
            // recDevId.toString(), recPort.toString());
            flood(context);

        } else {
            // MAC address found, install flow rule
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
        // 1. The frr0ConnectPoint (ovs1) and externalPort (ovs2) are on different
        // switches
        // 2. The veth link between ovs1 and ovs2 is not discovered by ONOS via LLDP
        // 3. Intents fail to compile with "Unable to compile intent" error
        // 4. The packet processor already correctly handles WAN IPv6 traffic using
        // packetOut
        if (!wanPeerIp6List.isEmpty() && wanLocalIp6 != null) {
            log.info("WAN IPv6 peering configured: local={}, peers={}", wanLocalIp6, wanPeerIp6List);
            log.info("WAN IPv6 traffic will be handled by packet processor (no intents)");
        }
    }

    /**
     * Install bidirectional flow rules for internal IPv4 peer traffic.
     * This enables BGP communication between frr0 and frr1 on the 192.168.63.0/24
     * network.
     * Uses direct flow rules instead of intents since both routers are on the same
     * switch.
     */
    private void installInternalPeerForwardingFlowRules() {
        if (internalV4Peers.isEmpty()) {
            log.info("No internal IPv4 peers configured");
            return;
        }

        if (frr0ConnectPoint == null || frr1ConnectPoint == null) {
            log.warn("Cannot install internal peer flow rules: frr0ConnectPoint={}, frr1ConnectPoint={}",
                    frr0ConnectPoint, frr1ConnectPoint);
            return;
        }

        // Both frr0 and frr1 should be on the same device for direct flow rules
        if (!frr0ConnectPoint.deviceId().equals(frr1ConnectPoint.deviceId())) {
            log.warn("frr0 and frr1 are on different devices, cannot use direct flow rules");
            return;
        }

        DeviceId deviceId = frr0ConnectPoint.deviceId();

        for (Ip4Address[] peerPair : internalV4Peers) {
            Ip4Address frr0InternalIp = peerPair[0]; // e.g., 192.168.63.1
            Ip4Address frr1InternalIp = peerPair[1]; // e.g., 192.168.63.2

            // Flow rule 1: Traffic to frr0's internal IP -> output to frr0 port
            TrafficSelector toFrr0Selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(frr0InternalIp, 32))
                    .build();

            TrafficTreatment toFrr0Treatment = DefaultTrafficTreatment.builder()
                    .setOutput(frr0ConnectPoint.port())
                    .build();

            FlowRule toFrr0Rule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(toFrr0Selector)
                    .withTreatment(toFrr0Treatment)
                    .withPriority(45)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(toFrr0Rule);
            log.info("Installed internal peer flow rule: to {} -> port {}",
                    frr0InternalIp, frr0ConnectPoint.port());

            // Flow rule 2: Traffic to frr1's internal IP -> output to frr1 port
            TrafficSelector toFrr1Selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(frr1InternalIp, 32))
                    .build();

            TrafficTreatment toFrr1Treatment = DefaultTrafficTreatment.builder()
                    .setOutput(frr1ConnectPoint.port())
                    .build();

            FlowRule toFrr1Rule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(toFrr1Selector)
                    .withTreatment(toFrr1Treatment)
                    .withPriority(45)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(toFrr1Rule);
            log.info("Installed internal peer flow rule: to {} -> port {}",
                    frr1InternalIp, frr1ConnectPoint.port());

            log.info("Internal IPv4 BGP forwarding enabled: {} <-> {}", frr0InternalIp, frr1InternalIp);
        }
    }

    /**
     * Install bidirectional PointToPointIntents for internal IPv6 peer traffic.
     * This enables BGP communication between frr0 and frr1 on the fd63::/64
     * network.
     */
    private void installInternalPeerForwardingIntents() {
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
            Ip6Address frr0InternalIp = peerPair[0]; // fd63::1
            Ip6Address frr1InternalIp = peerPair[1]; // fd63::2

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

    /**
     * Install flow rule to intercept packets where:
     * - dstMAC = frr0 MAC
     * - dstIP is in local SDN subnet (172.16.35.0/24) but NOT frr0's IP
     * (172.16.35.69)
     *
     * These packets are from AS65351 (h3) routed by frr0 to local hosts.
     * They need to be intercepted and handled by virtual gateway for proper L3
     * routing.
     */
    private void installVirtualGatewayInterceptRule() {
        if (frr0Mac == null || frr0ConnectPoint == null) {
            log.warn("Cannot install virtual gateway intercept rule: frr0Mac={}, frr0ConnectPoint={}",
                    frr0Mac, frr0ConnectPoint);
            return;
        }

        // Install on the device where frr0 is connected (ovs1)
        DeviceId deviceId = frr0ConnectPoint.deviceId();

        // Treatment: Send to controller for virtual gateway processing
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER)
                .build();

        // IPv4 intercept rule: dstMAC = frr0 MAC, dstIP in local SDN subnet
        if (localSdnPrefix != null && frr0Ip4 != null) {
            TrafficSelector selectorV4 = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchEthDst(frr0Mac)
                    .matchIPDst(localSdnPrefix)
                    .build();

            FlowRule flowRuleV4 = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV4)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(flowRuleV4);
            log.info("Installed virtual gateway IPv4 intercept rule on device {} for dstMAC={}, dstIP={}",
                    deviceId, frr0Mac, localSdnPrefix);
        }

        // IPv4 intercept rule for traditional network: dstMAC = frr0 MAC, dstIP in
        // traditional subnet
        if (localTraditionalPrefix != null) {
            TrafficSelector selectorV4Trad = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchEthDst(frr0Mac)
                    .matchIPDst(localTraditionalPrefix)
                    .build();

            FlowRule flowRuleV4Trad = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV4Trad)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(flowRuleV4Trad);
            log.info(
                    "Installed virtual gateway IPv4 intercept rule for traditional network on device {} for dstMAC={}, dstIP={}",
                    deviceId, frr0Mac, localTraditionalPrefix);
        }

        // IPv6 intercept rule: dstMAC = frr0 MAC, dstIP in local SDN IPv6 subnet
        if (localSdnPrefix6 != null && frr0Ip6 != null) {
            TrafficSelector selectorV6 = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchEthDst(frr0Mac)
                    .matchIPv6Dst(localSdnPrefix6)
                    .build();

            FlowRule flowRuleV6 = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV6)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(flowRuleV6);
            log.info("Installed virtual gateway IPv6 intercept rule on device {} for dstMAC={}, dstIP={}",
                    deviceId, frr0Mac, localSdnPrefix6);
        }

        // IPv6 intercept rule for traditional network: dstMAC = frr0 MAC, dstIP in
        // local traditional IPv6 subnet
        if (localTraditionalPrefix6 != null) {
            TrafficSelector selectorV6Trad = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV6)
                    .matchEthDst(frr0Mac)
                    .matchIPv6Dst(localTraditionalPrefix6)
                    .build();

            FlowRule flowRuleV6Trad = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selectorV6Trad)
                    .withTreatment(treatment)
                    .withPriority(50)
                    .fromApp(appId)
                    .makePermanent()
                    .build();

            flowRuleService.applyFlowRules(flowRuleV6Trad);
            log.info(
                    "Installed virtual gateway IPv6 intercept rule for traditional network on device {} for dstMAC={}, dstIP={}",
                    deviceId, frr0Mac, localTraditionalPrefix6);
        }
    }

    /**
     * Install per-host flow rule for packets from frr0 to local hosts.
     * This optimizes subsequent packets by handling them in the data plane.
     *
     * Flow rule matches:
     * - dstMAC = frr0 MAC
     * - dstIP = specific local host IP
     *
     * Actions:
     * - Rewrite srcMAC to virtualGatewayMac
     * - Rewrite dstMAC to host MAC
     * - Forward to host port
     */
    private void installFrr0ToLocalHostFlowRule(PacketContext context, Ip4Address dstIp,
            MacAddress dstMac, ConnectPoint outPoint) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

        // Only install flow rule if packet came from and goes to the same device
        if (!deviceId.equals(outPoint.deviceId())) {
            log.debug("Not installing flow rule: packet traverses devices {} -> {}",
                    deviceId, outPoint.deviceId());
            return;
        }

        // Selector: dstMAC = frr0 MAC, dstIP = specific host IP
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchEthDst(frr0Mac)
                .matchIPDst(IpPrefix.valueOf(dstIp, 32))
                .build();

        // Treatment: rewrite MACs and forward to host port
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualGatewayMac)
                .setEthDst(dstMac)
                .setOutput(outPoint.port())
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(60) // Higher priority than intercept rule (50) for specific host routing
                .fromApp(appId)
                .makeTemporary(30) // 30-second timeout
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Installed per-host flow rule on device {} for dstIP={} -> dstMAC={}, outPort={}",
                deviceId, dstIp, dstMac, outPoint.port());
    }

    /**
     * Install per-host IPv6 flow rule for packets from frr0 to local hosts.
     * This optimizes subsequent packets by handling them in the data plane.
     *
     * Flow rule matches:
     * - dstMAC = frr0 MAC
     * - dstIP = specific local host IPv6
     *
     * Actions:
     * - Rewrite srcMAC to virtualGatewayMac
     * - Rewrite dstMAC to host MAC
     * - Forward to host port
     */
    private void installFrr0ToLocalHostFlowRuleV6(PacketContext context, Ip6Address dstIp,
            MacAddress dstMac, ConnectPoint outPoint) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

        // Only install flow rule if packet came from and goes to the same device
        if (!deviceId.equals(outPoint.deviceId())) {
            log.debug("Not installing IPv6 flow rule: packet traverses devices {} -> {}",
                    deviceId, outPoint.deviceId());
            return;
        }

        // Selector: dstMAC = frr0 MAC, dstIP = specific host IPv6
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV6)
                .matchEthDst(frr0Mac)
                .matchIPv6Dst(IpPrefix.valueOf(dstIp, 128))
                .build();

        // Treatment: rewrite MACs and forward to host port
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(virtualGatewayMac)
                .setEthDst(dstMac)
                .setOutput(outPoint.port())
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId)
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(60) // Higher priority than intercept rule (50) for specific host routing
                .fromApp(appId)
                .makeTemporary(30) // 30-second timeout
                .build();

        flowRuleService.applyFlowRules(flowRule);
        log.info("Installed per-host IPv6 flow rule on device {} for dstIP={} -> dstMAC={}, outPort={}",
                deviceId, dstIp, dstMac, outPoint.port());
    }

}
