# Project Milestones

## 1. Intra-AS Communication
Hosts / switches within the same AS can ping each other with IPv4 and IPv6.

### AS65xx0
- `h2`, `h1`, `frr0` can ping each other using IPv4.
- `h2`, `h1`, `frr1` can ping each other using IPv6. 

Examples:
- Ping to `frr0` ip using IPv4: `docker exec h2 ping 172.16.35.69` 
- Ping to h2 using IPv6: `docker exec h1 ping -6 2a0b:4e07:c4:35::3`

### AS65xx1
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
TBD

## 4. Peer Network to Peer Network Communication
TBD

## 5. Anycast Traffic
TBD

## 6. Access the outside internet
TBD