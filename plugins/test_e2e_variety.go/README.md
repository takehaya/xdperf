# test_e2e_variety.go

A plugin that generates various protocol packets for end-to-end testing.

## Available Protocols

| Protocol | Description |
|---|---|
| `ipv4_udp` | IPv4 + UDP |
| `ipv6_udp` | IPv6 + UDP |
| `vlan` | 802.1Q VLAN tagged |
| `qinq` | QinQ (double VLAN) |
| `icmpv4` | ICMPv4 Echo Request |
| `icmpv6` | ICMPv6 Echo Request |
| `tcp` | IPv4 + TCP |
| `raw` | Raw Ethernet frame |
| `arp` | ARP |
| `eapol` | EAPoL |
| `lldp` | LLDP |
| `l2vpn` | L2VPN (MPLS with inner Ethernet) |
| `l3vpn` | L3VPN (MPLS with inner IP) |
| `l2vpn_srv6` | L2VPN over SRv6 |
| `l3vpn_srv6` | L3VPN over SRv6 |

## Usage

Send all protocols:

```bash
sudo xdperf run --device eth0 --plugin test_e2e_variety.go --pps 100 --duration 5s \
  --cfg '{"dst_ip":"192.168.1.2","src_ip":"192.168.1.1","dst_port":9999}'
```

Send specific protocols only:

```bash
sudo xdperf run --device eth0 --plugin test_e2e_variety.go --pps 10 --duration 2s \
  --cfg '{"dst_ip":"192.168.1.2","src_ip":"192.168.1.1","dst_port":9999,"protocols":["l2vpn_srv6","l3vpn_srv6"]}'
```
