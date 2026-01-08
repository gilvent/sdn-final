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
import org.onosproject.net.link.LinkService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Set;
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

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
    private ConnectPoint frr0ConnectPoint;
    private ConnectPoint frr1ConnectPoint;

    // Peer VXLAN configuration (for peer network communication)
    private ConnectPoint peer1VxlanCp;
    private ConnectPoint peer2VxlanCp;

    // Anycast configuration
    private Ip4Address anycastIp;
    private ConnectPoint anycast1ConnectPoint; // on ovs1
    private ConnectPoint anycast2ConnectPoint; // on ovs2
    private IpPrefix localSdnPrefix;
    private IpPrefix localSdnPrefix6;
    private IpPrefix peer1TraditionalPrefix;
    private IpPrefix peer2TraditionalPrefix;
    private IpPrefix peer1TraditionalPrefix6;
    private IpPrefix peer2TraditionalPrefix6;
    private List<String[]> v4Peers;
    private List<String[]> v6Peers;

    // Ingress filters: connect point -> list of allowed IP prefixes
    private Map<ConnectPoint, List<IpPrefix>> ingressFilters = new HashMap<>();
    // ARP ingress filters: connect point -> list of allowed ARP target IP prefixes
    private Map<ConnectPoint, List<IpPrefix>> arpIngressFilters = new HashMap<>();

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
            log.info("Loaded FRR config: frr0-mac={}, frr0-ip4={}, frr0-ip6={}",
                    frr0Mac, frr0Ip4, frr0Ip6);

            // Load peer VXLAN configuration
            peer1VxlanCp = config.peer1VxlanCp();
            peer2VxlanCp = config.peer2VxlanCp();
            localSdnPrefix = config.localSdnPrefix();

            // Load peer IPv6 SDN prefixes
            localSdnPrefix6 = config.localSdnPrefix6();

            // Load peer traditional prefixes
            peer1TraditionalPrefix = config.peer1TraditionalPrefix();
            peer2TraditionalPrefix = config.peer2TraditionalPrefix();
            peer1TraditionalPrefix6 = config.peer1TraditionalPrefix6();
            peer2TraditionalPrefix6 = config.peer2TraditionalPrefix6();

            // BGP peers IP
            v4Peers = config.v4Peers();
            v6Peers = config.v6Peers();

            // Load anycast configuration
            anycastIp = config.anycastIp();
            anycast1ConnectPoint = config.anycast1ConnectPoint();
            anycast2ConnectPoint = config.anycast2ConnectPoint();
            log.info("Loaded anycast config: ip={}, anycast1={}, anycast2={}",
                    anycastIp, anycast1ConnectPoint, anycast2ConnectPoint);

            installFrrToFpmFlowRules();

            // Load ingress filters
            loadIngressFilters(config);

            if (v4Peers != null && !v4Peers.isEmpty()) {
                installV4PeersIntents();
            }

            if (v6Peers != null && !v6Peers.isEmpty()) {
                installV6PeersIntents();
            }

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

    private boolean isPeerVxlanPort(ConnectPoint cp) {
        return (peer1VxlanCp != null && cp.equals(peer1VxlanCp)) ||
                (peer2VxlanCp != null && cp.equals(peer2VxlanCp));
    }

    private void loadIngressFilters(VRouterConfig config) {
        ingressFilters.clear();
        arpIngressFilters.clear();

        // Load filters for peer VXLAN ports
        if (peer1VxlanCp != null) {
            List<IpPrefix> filters = config.ingressFilters(peer1VxlanCp);
            if (!filters.isEmpty()) {
                ingressFilters.put(peer1VxlanCp, filters);
                log.info("Loaded ingress filters for {}: {}", peer1VxlanCp, filters);
            }
            List<IpPrefix> arpFilters = config.arpIngressFilters(peer1VxlanCp);
            if (!arpFilters.isEmpty()) {
                arpIngressFilters.put(peer1VxlanCp, arpFilters);
                log.info("Loaded ARP ingress filters for {}: {}", peer1VxlanCp, arpFilters);
            }
        }
        if (peer2VxlanCp != null) {
            List<IpPrefix> filters = config.ingressFilters(peer2VxlanCp);
            if (!filters.isEmpty()) {
                ingressFilters.put(peer2VxlanCp, filters);
                log.info("Loaded ingress filters for {}: {}", peer2VxlanCp, filters);
            }
            List<IpPrefix> arpFilters = config.arpIngressFilters(peer2VxlanCp);
            if (!arpFilters.isEmpty()) {
                arpIngressFilters.put(peer2VxlanCp, arpFilters);
                log.info("Loaded ARP ingress filters for {}: {}", peer2VxlanCp, arpFilters);
            }
        }

        // Load filters for WAN port
        if (externalPort != null) {
            List<IpPrefix> filters = config.ingressFilters(externalPort);
            if (!filters.isEmpty()) {
                ingressFilters.put(externalPort, filters);
                log.info("Loaded ingress filters for {}: {}", externalPort, filters);
            }
            List<IpPrefix> arpFilters = config.arpIngressFilters(externalPort);
            if (!arpFilters.isEmpty()) {
                arpIngressFilters.put(externalPort, arpFilters);
                log.info("Loaded ARP ingress filters for {}: {}", externalPort, arpFilters);
            }
        }
    }

    private boolean isAllowedIngress(ConnectPoint srcPoint, IpAddress dstIp) {
        List<IpPrefix> allowedPrefixes = ingressFilters.get(srcPoint);
        if (allowedPrefixes == null || allowedPrefixes.isEmpty()) {
            return true; // No filter configured, allow all
        }
        for (IpPrefix prefix : allowedPrefixes) {
            if (prefix.contains(dstIp)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAllowedArpIngress(ConnectPoint srcPoint, Ip4Address targetIp) {
        List<IpPrefix> allowedPrefixes = arpIngressFilters.get(srcPoint);
        if (allowedPrefixes == null || allowedPrefixes.isEmpty()) {
            return false; // No filter configured means block ARP on filtered ports
        }
        for (IpPrefix prefix : allowedPrefixes) {
            if (prefix.contains(targetIp)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAllowedNdpIngress(ConnectPoint srcPoint, Ip6Address targetIp) {
        List<IpPrefix> allowedPrefixes = ingressFilters.get(srcPoint);
        if (allowedPrefixes == null || allowedPrefixes.isEmpty()) {
            return false; // No filter configured means block NDP on filtered ports
        }
        for (IpPrefix prefix : allowedPrefixes) {
            if (prefix.contains(targetIp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract target IPv6 address from NDP packet (NS or NA).
     */
    private Ip6Address extractNdpTargetIp(ICMP6 icmp6) {
        byte type = icmp6.getIcmpType();
        if (type == ICMP6.NEIGHBOR_SOLICITATION) {
            NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
            return Ip6Address.valueOf(ns.getTargetAddress());
        } else if (type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
            org.onlab.packet.ndp.NeighborAdvertisement na = (org.onlab.packet.ndp.NeighborAdvertisement) icmp6
                    .getPayload();
            return Ip6Address.valueOf(na.getTargetAddress());
        }
        return null;
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

                // Apply ingress filter for peer VXLAN and WAN ports
                if (ingressFilters.containsKey(srcPoint)) {
                    if (!isAllowedIngress(srcPoint, dstIp)) {
                        return;
                    }
                    log.info("[Ingress Filter] Allowed IPv4 from {}: {} -> {}", srcPoint, srcIp, dstIp);
                }

                log.info("[DEBUG] IPv4 Packet from {}: srcIP={}, dstIP={}, srcMAC={}, dstMAC={}",
                        srcPoint, srcIp, dstIp, eth.getSourceMAC(), eth.getDestinationMAC());

                if (isAnycastIp(dstIp)) {
                    ConnectPoint ingressCP = context.inPacket().receivedFrom();
                    handleAnycastRouting(context, eth, ingressCP);
                    return;
                }

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
                Ip6Address dstIp = Ip6Address.valueOf(ipv6.getDestinationAddress());
                Ip6Address srcIp = Ip6Address.valueOf(ipv6.getSourceAddress());

                if (ipv6.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6 = (ICMP6) ipv6.getPayload();
                    byte type = icmp6.getIcmpType();

                    if (type == ICMP6.NEIGHBOR_SOLICITATION || type == ICMP6.NEIGHBOR_ADVERTISEMENT) {

                        if (ingressFilters.containsKey(srcPoint)) {
                            // NDP Solicitation are sent to multicast addresses (e.g: ff02::1:ff00:35)
                            // So we extract the target IP from NDP payload
                            Ip6Address targetIp = extractNdpTargetIp(icmp6);
                            if (targetIp == null || !isAllowedNdpIngress(srcPoint, targetIp)) {
                                return;
                            }
                            log.info("[NDP Ingress Filter] Allowed NDP from {} for target {}", srcPoint, targetIp);
                        }
                        handleNDP(context, eth);
                        return;
                    }
                }

                // Apply ingress filter for peer VXLAN and WAN ports (non-NDP IPv6)
                if (ingressFilters.containsKey(srcPoint)) {
                    if (!isAllowedIngress(srcPoint, dstIp)) {
                        return;
                    }
                    log.info("[Ingress Filter] Allowed IPv6 from {}: {} -> {}", srcPoint, srcIp, dstIp);
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
                    } else {
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

    private void sendNdpSolicitation(Ip6Address targetIp) {
        if (virtualGatewayIp6 == null) {
            log.warn("[Gateway] Cannot send NDP solicitation: virtualGatewayIp6 not configured");
            return;
        }

        log.info("[Gateway] Sending NDP solicitation for {} from virtual gateway", targetIp);

        Ethernet ndpSolicitation = buildNdpSolicitation(targetIp);

        Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();
        for (ConnectPoint cp : edgePoints) {
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
        ARP arp = (ARP) eth.getPayload();
        Ip4Address targetIp = Ip4Address.valueOf(arp.getTargetProtocolAddress());

        // Apply ARP ingress filter for peer VXLAN and WAN ports
        if (arpIngressFilters.containsKey(srcPoint)) {
            if (!isAllowedArpIngress(srcPoint, targetIp)) {
                return;
            }
            log.info("[ARP Ingress Filter] Allowed ARP from {} for target {}", srcPoint, targetIp);
        }

        MacAddress srcMac = eth.getSourceMAC();
        Ip4Address srcIp = Ip4Address.valueOf(arp.getSenderProtocolAddress());
        Ip4Address dstIp = targetIp;

        PortNumber srcPort = srcPoint.port();

        // Learn IP and MAC of sender host
        log.info("[ARP] Learned sender MAC {} from {} (port {})", srcMac, srcIp, srcPort);
        ipToMacTable.put(srcIp, srcMac);

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

            // Special handling for ARP to anycast server
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

    private void handleNDP(PacketContext context, Ethernet eth) {
        ConnectPoint srcPoint = context.inPacket().receivedFrom();
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

            if (virtualGatewayIp6 != null && dstIp.equals(virtualGatewayIp6)) {
                log.info("NDP Advertisement destined to virtual gateway IP {}.",
                        virtualGatewayIp6);
                return;
            }

            // Find requester's location using Ethernet destination MAC
            ConnectPoint dstHostPoint = findHostEdgePoint(dstMac);
            if (dstHostPoint == null) {
                // Try bridge table
                dstHostPoint = findConnectPointInBridgeTable(dstMac);
            }

            log.info("[NDP Advertisement] srcIP={}, dstIP={}, dstMAC={}", srcIp, dstIp, dstMac);

            if (dstHostPoint != null) {
                log.info("[NDP Advertisement] Forwarding to NS requester at {}", dstHostPoint);
                packetOut(dstHostPoint, eth);
            } else {
                log.warn("[NDP Advertisement]Cannot find requester location for dstMAC={}. Flood to edge ports",
                        dstMac);
                Iterable<ConnectPoint> edgePoints = edgePortService.getEdgePoints();

                for (ConnectPoint cp : edgePoints) {
                    if (cp.equals(srcPoint)) {
                        continue;
                    }

                    packetOut(cp, eth);
                }
                return;
            }

            return;
        }

        if (type == ICMP6.NEIGHBOR_SOLICITATION) {
            NeighborSolicitation ns = (NeighborSolicitation) icmp6.getPayload();
            byte[] targetBytes = ns.getTargetAddress();
            Ip6Address targetIp = Ip6Address.valueOf(targetBytes);

            // For DAD packets, do NOT send proxy reply - just flood to let DAD complete
            if (isDadPacket) {
                log.info("DAD Neighbor Solicitation for {}. Drop.", targetIp);
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

    private boolean isAnycastIp(Ip4Address dstIp) {
        return anycastIp != null && dstIp.equals(anycastIp);
    }

    private ConnectPoint selectNearestAnycastServer(ConnectPoint ingressCP) {
        if (anycast1ConnectPoint == null || anycast2ConnectPoint == null) {
            log.warn("Anycast connect points not configured");
            return null;
        }

        DeviceId ingressDevice = ingressCP.deviceId();
        String ingressDevStr = ingressDevice.toString();

        int distanceToAnycast1; // anycast1 on ovs1
        int distanceToAnycast2; // anycast2 on ovs2

        if (ingressDevStr.contains("0000000000000001")) {
            // Traffic arrived at ovs1 (h2, frr0, frr1)
            distanceToAnycast1 = 0; // same switch
            distanceToAnycast2 = 1; // ovs1 -> ovs2
        } else if (ingressDevStr.contains("0000000000000002")) {
            // Traffic arrived at ovs2 (h1, peer VXLAN)
            distanceToAnycast1 = 1; // ovs2 -> ovs1
            distanceToAnycast2 = 0; // same switch
        } else {
            // Unknown device, default to anycast1 (on ovs1)
            log.warn("Unknown ingress device: {}. Defaulting to anycast1.", ingressDevice);
            return anycast1ConnectPoint;
        }

        ConnectPoint selected = (distanceToAnycast1 <= distanceToAnycast2)
                ? anycast1ConnectPoint
                : anycast2ConnectPoint;

        log.info("Anycast selection: ingress={}, dist1={}, dist2={}, selected={}",
                ingressCP, distanceToAnycast1, distanceToAnycast2, selected);

        return selected;
    }

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
            routePacket(context, eth, serverMac, nearestServer);
        } else {
            log.warn("Anycast server MAC not found at {}. Flooding.", nearestServer);
            flood(context);
        }
    }

    private void routeToLocalSubnet(PacketContext context, Ethernet eth) {
        IPv4 ipv4 = (IPv4) eth.getPayload();
        Ip4Address dstIp = Ip4Address.valueOf(ipv4.getDestinationAddress());
        Ip4Address srcIp = Ip4Address.valueOf(ipv4.getSourceAddress());
        DeviceId ingressDevice = context.inPacket().receivedFrom().deviceId();

        log.info("[Gateway] Routing packet to local subnet: src {} -> dst {} on device {}",
                srcIp, dstIp, ingressDevice);

        // Check if destination is anycast IP
        if (isAnycastIp(dstIp)) {
            ConnectPoint ingressCP = context.inPacket().receivedFrom();
            handleAnycastRouting(context, eth, ingressCP);
            return;
        }

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
        Ip6Address nextHopIp6 = nextHop.getIp6Address();

        if (nextHopIp6.isLinkLocal()) {
            log.info("[Gateway] L3 IPv6: Next-hop {} is link-local.",
                    nextHopIp6);
        }

        // Use HostService to resolve next-hop MAC (more reliable for link-local
        // addresses)
        MacAddress dstMac = null;
        Set<Host> hosts = hostService.getHostsByIp(nextHopIp6);
        if (!hosts.isEmpty()) {
            dstMac = hosts.iterator().next().mac();
            log.info("[Gateway] L3 IPv6: Resolved next-hop {} MAC via HostService: {}", nextHopIp6, dstMac);
        }

        if (dstMac == null) {
            dstMac = ip6ToMacTable.asJavaMap().get(nextHopIp6);
            if (dstMac != null) {
                log.info("[Gateway] L3 IPv6: Resolved next-hop {} MAC via ip6ToMacTable: {}", nextHopIp6, dstMac);
            }
        }

        if (dstMac == null) {
            log.warn("[Gateway] L3 IPv6: MAC for next-hop {} not found. Dropping",
                    nextHopIp6);
            return;
        }

        log.info("[Gateway] L3 IPv6: Found NEXT-HOP MAC {}.", dstMac);
        ConnectPoint outPoint = findIp6NextHopOutput(eth, nextHopIp6);

        if (outPoint == null) {
            log.warn("[Gateway] L3 IPv6: Cannot find output interface for nextHop {}. Drop packet.", nextHopIp6);
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
     * Build a mapping from peer IPs to their configured connect points.
     * This avoids race conditions with InterfaceService by using explicitly
     * configured values from VRouterConfig.
     */
    private Map<IpAddress, ConnectPoint> buildPeerIpToConnectPointMap() {
        Map<IpAddress, ConnectPoint> map = new HashMap<>();

        // Map peer VXLAN IPs to their connect points
        if (peer1VxlanCp != null) {
            // peer1 uses 192.168.70.34 (IPv4) and fd70::34 (IPv6)
            map.put(IpAddress.valueOf("192.168.70.34"), peer1VxlanCp);
            map.put(IpAddress.valueOf("fd70::34"), peer1VxlanCp);
        }
        if (peer2VxlanCp != null) {
            // peer2 uses 192.168.70.36 (IPv4) and fd70::36 (IPv6)
            map.put(IpAddress.valueOf("192.168.70.36"), peer2VxlanCp);
            map.put(IpAddress.valueOf("fd70::36"), peer2VxlanCp);
        }

        // Map WAN/external IPs to external port
        if (externalPort != null) {
            // AS65000 transit uses 192.168.70.253 (IPv4) and fd70::fe (IPv6)
            map.put(IpAddress.valueOf("192.168.70.253"), externalPort);
            map.put(IpAddress.valueOf("fd70::fe"), externalPort);
        }

        // Map frr1 (internal iBGP peer) to frr1 connect point
        if (frr1ConnectPoint != null) {
            // frr1 uses 192.168.63.2 (IPv4) and fd63::2 (IPv6)
            map.put(IpAddress.valueOf("192.168.63.2"), frr1ConnectPoint);
            map.put(IpAddress.valueOf("fd63::2"), frr1ConnectPoint);
        }

        return map;
    }

    private void installV4PeersIntents() {
        if (v4Peers == null || v4Peers.isEmpty()) {
            log.info("No v4-peers configured for intent installation");
            return;
        }

        if (frr0ConnectPoint == null) {
            log.warn("Cannot install v4 peer intents: frr0ConnectPoint not configured");
            return;
        }

        // Build mapping from peer IPs to connect points using explicit config
        Map<IpAddress, ConnectPoint> peerIpToCp = buildPeerIpToConnectPointMap();
        log.info("Peer IP to ConnectPoint mapping: {}", peerIpToCp);

        int installedCount = 0;
        for (String[] peer : v4Peers) {
            Ip4Address localIp = Ip4Address.valueOf(peer[0]);
            Ip4Address peerIp = Ip4Address.valueOf(peer[1]);

            // Use explicit mapping instead of InterfaceService lookup
            ConnectPoint localCp = frr0ConnectPoint; // Local IPs always come from frr0
            ConnectPoint peerCp = peerIpToCp.get(peerIp);

            log.info("v4-peer: local={} (cp={}), peer={} (cp={})", localIp, localCp, peerIp, peerCp);

            if (peerCp == null) {
                log.warn("No connect point configured for peer IP {}, skipping", peerIp);
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
     * Install PointToPointIntents for IPv6 BGP peers exchange.
     * Uses explicitly configured connect points to avoid race conditions
     * with InterfaceService:
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

        // Build mapping from peer IPs to connect points using explicit config
        Map<IpAddress, ConnectPoint> peerIpToCp = buildPeerIpToConnectPointMap();

        int installedCount = 0;
        for (String[] peer : v6Peers) {
            Ip6Address localIp = Ip6Address.valueOf(peer[0]);
            Ip6Address peerIp = Ip6Address.valueOf(peer[1]);

            // Use explicit mapping instead of InterfaceService lookup
            ConnectPoint localCp = frr0ConnectPoint; // Local IPs always come from frr0
            ConnectPoint peerCp = peerIpToCp.get(peerIp);

            log.info("v6-peer: local={} (cp={}), peer={} (cp={})", localIp, localCp, peerIp, peerCp);

            if (peerCp == null) {
                log.warn("No connect point configured for peer IP {}, skipping", peerIp);
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
