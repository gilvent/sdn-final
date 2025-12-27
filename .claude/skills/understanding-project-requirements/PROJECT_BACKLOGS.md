# Project Backlogs

## 1. Intra-AS Communication
Hosts / switches within the same AS can ping each other with IPv4 and IPv6.

### AS65xx0
Requirements:
- `h2`, `h1`, `frr0` can ping each other using IPv4.
- `h2`, `h1`, `frr1` can ping each other using IPv6. 

Examples:
- Ping to `frr0` ip using IPv4: `docker exec h2 ping 172.16.35.69` 
- Ping to h2 using IPv6: `docker exec h1 ping -6 2a0b:4e07:c4:35::3`

### AS65xx1
Requirements:
- `h3` and `frr1` can ping each other using IPv4
- `h3` and `frr1` can ping each other using IPv6

Examples:
- Ping to `frr1` ip using IPv4: `docker exec h3 ping 172.17.35.1`
- Ping to h3 using IPv6: `docker exec frr1 ping -6 2a0b:4e07:c4:135::2`

## 2. AS65xx1 - AS65xx0 FRR Router Communication
`frr1` from `AS65xx1` should be able to communicate with `frr0` from `AS65xx0`.

Requirements:
- `frr1` and `frr0` can ping each other using IPv4 and IPv6.
- Enable BGP exchange between two AS.

Examples:
- Ping using IPv4: `docker exec frr0 ping 192.168.63.2`
- Ping using IPv6: `docker exec frr1 ping -6 fd63::1`
- Verify BGP summary: `sudo make status`

## 3. AS65xx1 - AS65xx0 Hosts Communication
Upon successful BGP exchange, hosts in `AS65xx1` and `AS65xx0` can ping each other with IPv4 and IPv6. 

Requirements:
- Inter AS routing in `AS65xx0` handled by `vrouter` virtual gateway function, not `frr0`
- `vrouter` obtain `frrouting`s routing info using FPM

Examples:
- `h3` ping to `h2`: `docker exec h3 ping 172.16.35.3`
- `h1` ping to `h3`: `docker exec h1 ping -6 2a0b:4e07:c4:135::2`

## 3. BGP Peering with AS65000
`frr0` can communicate and establish BGP session with a BGP speaker in `AS65000`.

Requirements:
- `frr0` announces its networks to BGP speaker in `AS65000`. BGP speaker status are observed in IXP manager.
- `frr0` technically can ping to `AS65000` BGP speaker using IPv4 and IPv6.
- Whitelisting traffic incoming to `ovs3` based on source and destination may be necessary
- ARP handling by `vrouter` proxy ARP approach
- NDP handling by `vrouter` proxy NDP approach. Consider that Neighbor Advertisement may use multicast address.
- Forwarding between `ovs3` and `frr0` using MultiPointToSinglePoint intent may be necessary.
- Obtaining `ovs3` interface from network config based on IP may be necessary.
- Only advertise `AS65xx0` and `AS65xx1` network prefixes to `AS65000` BGP


Examples:
- `frr0` ping to `AS65000` BGP speaker (IPv4): `docker exec frr0 ping 192.168.70.253`
- `frr0` ping to `AS65000` BGP speaker (IPv6): `docker exec frr0 ping -6 fd70::fe`
- Verify `frr0` BGP summary: `sudo make status`
- BGP status observed in IXP manager:

```
   "pb_0035_as65350": {
      "protocol": "pb_0035_as65350",
      "bird_protocol": "BGP",
      "table": "t_0035_as65350",
      "state": "start",
      "state_changed": "2025-12-23T00:00:00+00:00",
      "connection": "Connect",
      "description": "AS65350 - SDN-USER-35",
      "preference": 100,
      "input_filter": "(unnamed)",
      "output_filter": "ACCEPT",
      "import_limit": 2,
      "limit_action": "restart",
      "routes": {
        "imported": 0,
        "exported": 0,
        "preferred": 0
      },
      "route_changes": {
        "import_updates": {
          "received": 0,
          "rejected": 0,
          "filtered": 0,
          "ignored": 0,
          "accepted": 0
        },
        "import_withdraws": {
          "received": 0,
          "rejected": 0,
          "ignored": 0,
          "accepted": 0
        },
        "export_updates": {
          "received": 0,
          "rejected": 0,
          "filtered": 0,
          "accepted": 0
        },
        "export_withdraws": {
          "received": 0,
          "accepted": 0
        }
      },
      "bgp_state": "Connect",
      "neighbor_address": "192.168.70.35",
      "neighbor_as": 65350
    },
```

## 4. BGP Peering with Peer Networks
`frr0` between peer networks (id = `34`, id = `35`, id = `36`) can establish BGP session and ping each other using IPv4 and IPv6

Requirements:
- Outgoing traffic goes through dedicated VXLAN on `ovs2`
- Incoming traffic comes from dedicated VXLAN on `ovs2`
- Only advertise AS65xx0 network to peer BGP. Do not advertise AS65xx1's.

Examples:
- Check received routes: `docker exec frr0 vtysh -c "show ip bgp nei 192.168.70.34 routes"`
- Check advertised routes: `docker exec frr0 vtysh -c "show bgp ipv6 nei fd70::36 adv"`

## 5. Peer Networks Communication
Hosts between peer networks (id = `34`, id = `35`, id = `36`)can ping each other using IPv4 and IPv6

### Destination is Peer Network's AS65xx0
Requirements:
- Outgoing traffic path should go through `ovs2` peer VXLAN
- Outgoing traffic path should not go through AS65000 (`ovs3`)
- Incoming traffic path depends on source host (because peer network runs the same topology)
    - Source is AS65xx1 (`h3`): Traffic comes in from AS65000
    - Source is AS65xx0 (`h2` and `h1`): Traffic comes in from `ovs2` peer VXLAN

Examples:
- Ping to AS65340 from AS65351: `docker exec h3 ping 172.16.34.2`
- Ping to AS65360 from AS65350 (Ipv6): `docker exec h2 ping -6 2a0b:4e07:c4:36::2`

### Destination is peer network's AS65xx1
Requirements:
- Outgoing traffic path should go through AS65000 (`ovs3`)
- Outgoing traffic path should not go through `ovs2` peer VXLAN
- Incoming traffic path depends on source host (because peer network runs the same topology)
    - Source is AS65xx1 (`h3`): Traffic comes in from AS65000
    - Source is AS65xx0 (`h2` and `h1`): Traffic comes in from `ovs2` peer VXLAN

Examples:
- Ping to AS65341 from AS65350: `docker exec h2 ping 172.17.34.2`
- Ping to AS65361 from AS65351 (IPv6): `docker exec h3 ping 2a0b:4e07:c4:136::2`

## 6. Anycast Traffic
TBD

## 6. Access the outside internet
TBD