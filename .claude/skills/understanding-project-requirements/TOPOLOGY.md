# Network Topology

The environment consists of two main Autonomous Systems (AS), an SDN controller, and various hosts and routers.

## High-Level Overview

-   **Network ID**: This topology's network id is `35`. Every reference to `xx` refers to `35`. For example, AS65xx0 means AS65350.
-   **AS65xx0**: An SDN-based network controlled by the ONOS vRouter application. It contains two hosts (`h1`, `h2`), two Open vSwitch (OVS) bridges (`ovs1`, `ovs2`), and a border router (`frr0`).
-   **AS65xx1**: A traditionally routed network with one host (`h3`) and one router (`frr1`).
-   **SDN Controller**: An `onos` instance that manages `ovs1`, `ovs2` and `ovs3`. It runs a custom `vrouter` application that provides L2/L3 services within AS65350.
-   **Peer Networks**: External networks running the same topology setup with id `34` and `36`.
-   **AS65000 / Transit Network**: An external network bridging multiple AS65xx0 networks. `ovs3` of each AS65xx0 network is part of transit network.
-   **Inter-AS Connectivity**: AS65xx0 and AS65xx1 are connected via their border routers (`frr0` and `frr1`), which peer using eBGP.
-   **Transit Network Connectivity**: AS65xx0 (`frr0`) has a BGP session with a BGP speaker in AS65000. Physical connectivity is achieved using VXLAN on top of Wireguard tunnel between `ovs2` and `ovs3`.
-   **Peer Connectivity**: AS65xx0 (`ovs2`) is connected to peer networks' AS65xx0 (`ovs2`) using VXLAN on top of Wireguard tunnel.

## Components and IP Addressing

---

### AS65xx0 (SDN Domain)

-   **Subnets**: `172.16.xx.0/24` (Internal), `2a0b:4e07:c4:xx::/64` (Internal IPv6)
-   **Controller**: `onos`
-   **Switches**: `ovs1`, `ovs2`
-   **Router**: `frr0` (r0)
-   **Hosts**: `h1`, `h2`

#### SDN Controller (ONOS)

-   **Docker Container**: `onos`
-   **Connection**: Manages `ovs1` and `ovs2` via OpenFlow, listening on `tcp:127.0.0.1:6653`.
-   **vRouter App**: Provides a virtual gateway for hosts in AS65xx0.
    -   **Virtual Gateway MAC**: `00:00:00:00:00:02`
    -   **Virtual Gateway IPv4**: `172.16.xx.1`
    -   **Virtual Gateway IPv6**: `2a0b:4e07:c4:xx::1`

#### OVS Switches

-   **ovs1**: Connects `h2`, `frr0`, and `frr1`.
-   **ovs2**: Connects `h1`.
-   **ovs3**: Connects AS65000.
-   **Link**: `ovs1` and `ovs2` are connected by a `veth` pair (`ovs1-ovs2-veth`, `ovs2-ovs1-veth`).
-   **Tunnel Link**: `ovs2` and `ovs3` are connected via VXLAN on top of Wireguard tunnel
-   **Peer VXLAN**: `ovs2` are connected to Peer's `ovs2` through dedicated VXLAN

#### Hosts

-   **h1**:
    -   **Connection**: `ovs2`
    -   **IPv4**: `172.16.xx.2/24`
    -   **IPv6**: `2a0b:4e07:c4:xx::2/64`
    -   **Default Gateway**: `172.16.xx.1` (vRouter), `2a0b:4e07:c4:xx::1` (vRouter)

-   **h2**:
    -   **Connection**: `ovs1`
    -   **IPv4**: `172.16.xx.3/24`
    -   **IPv6**: `2a0b:4e07:c4:xx::3/64`
    -   **Default Gateway**: `172.16.xx.1` (vRouter), `2a0b:4e07:c4:xx::1` (vRouter)


#### Router (frr0)

-   **BGP AS**: `65xx0`
-   **Router-ID**: `192.168.63.1`
-   **Connection**: `ovs1` (on interface `eth0`)
-   **MAC Address**: `00:00:00:00:00:01`
-   **IP Addresses on `eth0`**:
    -   `192.168.63.1/24` (for peering with `frr1`)
    -   `172.16.xx.69/24` (for routing from vRouter)
    -   `192.168.100.3/24` (for pushing routing information to SDN Controller)
    -   `192.168.70.xx/24` (for VXLAN to AS65000 `ovs3`)
    -   `fd63::1/64` (for IPv6 peering with `frr1`)
    -   `fd70::xx/64` (for IPv6 peering with AS65000)
    -   `2a0b:4e07:c4:xx::69/64` (for IPv6 routing from vRouter)
-   **BGP Neighbors**:
    -   `frr1` (AS65xx1) at `192.168.63.2` and `fd63::2`.
    -   External Peer (AS65000) at `192.168.70.253` and `fd70::fe`.

---

### AS65351 (Traditional Domain)

-   **Subnet**: `172.17.xx.0/24`, `2a0b:4e07:c4:1xx::/64` (IPv6)
-   **Router**: `frr1` (r1)
-   **Host**: `h3`

#### Host (h3)

-   **Connection**: `frr1` (direct `veth` link)
-   **IPv4**: `172.17.xx.2/24`
-   **IPv6**: `2a0b:4e07:c4:1xx::2/64`
-   **Default Gateway**: `172.17.xx.1` (`frr1`), `2a0b:4e07:c4:1xx::1` (`frr1`)

#### Router (frr1)

-   **BGP AS**: `65xx1`
-   **Router-ID**: `192.168.63.2`
-   **Connections**:
    -   `eth1` -> `h3`
    -   `eth0` -> `ovs1`
-   **IP Addresses**:
    -   `eth1` (Intra-AS): `172.17.xx.1/24`, `2a0b:4e07:c4:1xx::1/64`
    -   `eth0` (Inter-AS): `192.168.63.2/24`, `fd63::2/64`
-   **BGP Neighbors**:
    -   `frr0` (AS65350) at `192.168.63.1` and `fd63::1`.

---

## Links and Connectivity Summary

| From     | To          | Type              | Subnet(s)                                                                                                                                  | Notes                                                               |
| :------- | :---------- | :---------------- | :----------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------ |
| `h1`     | `ovs2`      | Virtual Ethernet  | `172.16.35.0/24`, `2a0b:4e07:c4:35::/64`                                                                                                    | Host port                                                           |
| `h2`     | `ovs1`      | Virtual Ethernet  | `172.16.35.0/24`, `2a0b:4e07:c4:35::/64`                                                                                                    | Host port                                                           |
| `frr0`   | `ovs1`      | Virtual Ethernet  | `192.168.63.0/24`, `172.16.35.0/24`, `fd63::/64`                                                                                            | Router port                                                         |
| `frr1`   | `ovs1`      | Virtual Ethernet  | `192.168.63.0/24`, `fd63::/64`                                                                                                              | Boundary router port                                                |
| `ovs1`   | `ovs2`      | Veth Pair         | N/A (L2 Link)                                                                                                                              | Trunk between switches                                              |
| `h3`     | `frr1`      | Veth Pair         | `172.17.35.0/24`, `2a0b:4e07:c4:135::/64`                                                                                                   | Direct host-router link                                             |
| `onos`   | `ovs1, ovs2`| Docker Port Map   | `tcp:127.0.0.1:6653`                                                                                                                       | OpenFlow controller link                                            |
| `ovs2`   | (External)  | VXLAN Tunnel      | `remote_ip=192.168.60.35`, `local_ip=192.168.61.35`                                                                                        | Tunnel to a remote OVS instance                                     |

