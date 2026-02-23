package packets

// Protocol identifiers
const (
	ProtoIPv4UDP   = "ipv4_udp"
	ProtoIPv6UDP   = "ipv6_udp"
	ProtoVLAN      = "vlan"
	ProtoQinQ      = "qinq"
ProtoICMPv4    = "icmpv4"
	ProtoICMPv6    = "icmpv6"
	ProtoTCP       = "tcp"
	ProtoRaw       = "raw"
ProtoARP       = "arp"
	ProtoEAPoL     = "eapol"
	ProtoLLDP      = "lldp"
	ProtoL2VPN     = "l2vpn"
	ProtoL3VPN     = "l3vpn"
	ProtoL2VPNSRv6 = "l2vpn_srv6"
	ProtoL3VPNSRv6 = "l3vpn_srv6"
)

// Registry maps protocol names to their variant builders
var Registry = map[string]VariantBuilder{
	ProtoIPv4UDP:   BuildIPv4UDPVariant,
	ProtoIPv6UDP:   BuildIPv6UDPVariant,
	ProtoVLAN:      BuildVLANVariant,
	ProtoQinQ:      BuildQinQVariant,
ProtoICMPv4:    BuildICMPv4Variant,
	ProtoICMPv6:    BuildICMPv6Variant,
	ProtoTCP:       BuildTCPVariant,
	ProtoRaw:       BuildRawVariant,
ProtoARP:       BuildARPVariant,
	ProtoEAPoL:     BuildEAPoLVariant,
	ProtoLLDP:      BuildLLDPVariant,
	ProtoL2VPN:     BuildL2VPNVariant,
	ProtoL3VPN:     BuildL3VPNVariant,
	ProtoL2VPNSRv6: BuildL2VPNSRv6Variant,
	ProtoL3VPNSRv6: BuildL3VPNSRv6Variant,
}

// AllProtocols returns a list of all supported protocol identifiers
func AllProtocols() []string {
	return []string{
		ProtoIPv4UDP,
		ProtoIPv6UDP,
		ProtoVLAN,
		ProtoQinQ,
ProtoICMPv4,
		ProtoICMPv6,
		ProtoTCP,
		ProtoRaw,
ProtoARP,
		ProtoEAPoL,
		ProtoLLDP,
		ProtoL2VPN,
		ProtoL3VPN,
		ProtoL2VPNSRv6,
		ProtoL3VPNSRv6,
	}
}
