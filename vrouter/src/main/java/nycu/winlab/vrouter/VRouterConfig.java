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
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.Config;

/**
 * Configuration for the VRouter application.
 */
public class VRouterConfig extends Config<ApplicationId> {

    private static final String FRR0_CONNECT_POINT = "frr0-connect-point";
    private static final String FRR_ZERO_MAC = "frr0-mac";
    private static final String FRR_ZERO_IP4 = "frr0-ip4";
    private static final String FRR_ZERO_IP6 = "frr0-ip6";
    private static final String VIRTUAL_GATEWAY_IP4 = "virtual-gateway-ip4";
    private static final String VIRTUAL_GATEWAY_IP6 = "virtual-gateway-ip6";
    private static final String VIRTUAL_GATEWAY_MAC = "virtual-gateway-mac";
    private static final String EXTERNAL_PORT = "external-port";

    @Override
    public boolean isValid() {
        return hasOnlyFields(FRR0_CONNECT_POINT,FRR_ZERO_MAC, FRR_ZERO_IP4, FRR_ZERO_IP6,
                VIRTUAL_GATEWAY_IP4, VIRTUAL_GATEWAY_IP6,
                VIRTUAL_GATEWAY_MAC, EXTERNAL_PORT);
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
        String port = get(EXTERNAL_PORT, null);
        return port != null ? ConnectPoint.deviceConnectPoint(port) : null;
    }
}
