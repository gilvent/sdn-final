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
import java.util.HashMap;
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
    private MacAddress quaggaMac;
    private Ip4Address quaggaIp4;
    private Ip6Address quaggaIp6;

    // External port (interface port) where ARP/NDP should be dropped
    private ConnectPoint externalPort;

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
            quaggaMac = config.quaggaMac();
            quaggaIp4 = config.quaggaIp4();
            quaggaIp6 = config.quaggaIp6();
            externalPort = config.externalPort();
            log.info("Loaded VRouter config: gateway-ip4={}, gateway-ip6={}, gateway-mac={}",
                    virtualGatewayIp4, virtualGatewayIp6, virtualGatewayMac);
            log.info("Loaded Quagga config: quagga-mac={}, quagga-ip4={}, quagga-ip6={}",
                    quaggaMac, quaggaIp4, quaggaIp6);
            log.info("Loaded external port config: external-port={}", externalPort);

            // Pre-populate quagga IP-MAC mappings for L3 routing
            if (quaggaIp4 != null && quaggaMac != null && ipToMacTable != null) {
                ipToMacTable.put(quaggaIp4, quaggaMac);
                log.info("Pre-populated quagga IPv4 mapping: {} -> {}", quaggaIp4, quaggaMac);
            }
            if (quaggaIp6 != null && quaggaMac != null && ip6ToMacTable != null) {
                ip6ToMacTable.put(quaggaIp6, quaggaMac);
                log.info("Pre-populated quagga IPv6 mapping: {} -> {}", quaggaIp6, quaggaMac);
            }
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
                // Check if this is L3 routing (destination is our virtual gateway MAC)
                if (virtualGatewayMac != null && eth.getDestinationMAC().equals(virtualGatewayMac)) {
                    
                    handleL3RoutingIPv4(context, eth);
                    return;
                }
                handleLearningBridge(context, eth);
                return;
            }

            // Handle IPv6 packets (for NDP)
            if (eth.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6 = (IPv6) eth.getPayload();
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

        // Drop ARP packets from external/interface port
        if (externalPort != null && srcPoint.equals(externalPort)) {
            // log.info("Dropping ARP from external port: {}", srcPoint);
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

    private void handleNDP(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();

        // Drop NDP packets from external/interface port
        if (externalPort != null && srcPoint.equals(externalPort)) {
            log.info("Dropping NDP from external port: {}", srcPoint);
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
                log.info("NDP TABLE HIT. Requested MAC = {}", cachedDstMac);

                Ethernet ndpAdv = NeighborAdvertisement2.buildNdpAdv(targetIp, cachedDstMac, context.inPacket().parsed());
                ConnectPoint outCp = context.inPacket().receivedFrom();

                packetOut(outCp, ndpAdv);
            } else {
                log.info("NDP TABLE MISS. Send NDP Solicitation to edge ports");

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
        } else if (quaggaMac != null) {
            // Default route: forward to the pre-configured Quagga/FRR router
            log.info("L3 IPv4 REMOTE: IP {} not in table. Forwarding to default quagga router (MAC={})", dstIp, quaggaMac);
            routePacket(context, eth, quaggaMac);
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
        } else if (quaggaMac != null) {
            // Default route: forward to the pre-configured Quagga/FRR router
            log.info("L3 IPv6 REMOTE: IP {} not in table. Forwarding to default quagga router (MAC={})", dstIp, quaggaMac);
            routePacket(context, eth, quaggaMac);
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

}
