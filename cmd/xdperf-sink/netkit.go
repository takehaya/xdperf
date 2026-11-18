package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	nkFastpathMu       sync.Mutex
	nkFastpathLinks    []link.Link
	nkFastpathProgs    []*ebpf.Program
	nkIngressFlowMap   *ebpf.Map
	nkEgressFlowMap    *ebpf.Map
	nkFastpathDumpPath string
)

const (
	skbProtocolOffset = 16 // offsetof(struct __sk_buff, protocol)
	skbDataOffset     = 76 // offsetof(struct __sk_buff, data)
	skbDataEndOffset  = 80 // offsetof(struct __sk_buff, data_end)
	ethHLen           = 14
	ipv4HLen          = 20
	l4PortsLen        = 4
	ethProtoOffset    = 12
	ipv4DaddrOffset   = 30 // 14 (eth) + 16 (offsetof(struct iphdr, daddr))
	ipprotoTCP        = 6
	ipprotoUDP        = 17
	flowMapMaxEntries = 65536
)

// netkitFlowKey5 matches the 16-byte 5-tuple key layout used by the BPF
// LRU_HASH flow counter (network byte order for IP/port fields).
type netkitFlowKey5 struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Proto uint8
	Pad   [3]uint8
}

// netkitFlowEntry is the JSON representation written by -netkit-flow-dump.
type netkitFlowEntry struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   uint8  `json:"proto"`
	Packets uint64 `json:"packets"`
}

// netkitFlowDump holds per-flow 5-tuple packet counts recorded at the TCX
// ingress hook (into the netkit Pod) and the BPF_NETKIT_PEER hook (out of the
// netkit Pod, equivalent to Cilium's cil_from_container hook).
type netkitFlowDump struct {
	Ingress []netkitFlowEntry `json:"ingress"`
	Egress  []netkitFlowEntry `json:"egress"`
}

// attachNetkitFastpath attaches a minimal Cilium-style BPF redirect fastpath
// without flow counting.
func attachNetkitFastpath(spec string) error {
	return attachNetkitFastpathWithFlows(spec, "")
}

// attachNetkitFastpathWithFlows attaches a Cilium-style BPF redirect fastpath
// on a router/host namespace bridging an ingress device (e.g. veth/NIC) and a
// primary netkit device:
//   - TCX ingress on ingressDev: IPv4 packets to podIP -> bpf_redirect_peer(netkitPrimaryIfindex, 0)
//   - Netkit peer on netkitPrimaryDev: IPv4 packets from the Pod -> bpf_redirect_neigh(ingressIfindex, NULL, 0, 0)
//
// When flowDumpPath is non-empty, both programs also count per-flow IPv4 TCP/UDP
// 5-tuples in 65,536-entry BPF_MAP_TYPE_LRU_HASH maps (mirroring a Cilium
// Datapath Plugin flow collector) and dump the counts as JSON on detach.
//
// Format of spec: "<ingress-dev>:<netkit-primary-dev>:<pod-ipv4>"
func attachNetkitFastpathWithFlows(spec, flowDumpPath string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("invalid -netkit-fastpath %q (expected <ingress-dev>:<netkit-primary-dev>:<pod-ipv4>)", spec)
	}
	inDev, err := net.InterfaceByName(parts[0])
	if err != nil {
		return fmt.Errorf("ingress device %s: %w", parts[0], err)
	}
	nkDev, err := net.InterfaceByName(parts[1])
	if err != nil {
		return fmt.Errorf("netkit device %s: %w", parts[1], err)
	}
	ip := net.ParseIP(parts[2]).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address %q", parts[2])
	}
	ethPIP := int32(binary.NativeEndian.Uint16([]byte{0x08, 0x00}))
	podIP := int32(binary.NativeEndian.Uint32(ip))

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	var inMap, egMap *ebpf.Map
	if flowDumpPath != "" {
		mapSpec := &ebpf.MapSpec{
			Name:       "nk_flow5_in",
			Type:       ebpf.LRUHash,
			KeySize:    16,
			ValueSize:  8,
			MaxEntries: flowMapMaxEntries,
		}
		inMap, err = ebpf.NewMap(mapSpec)
		if err != nil {
			return fmt.Errorf("create ingress flow map: %w", err)
		}
		egSpec := *mapSpec
		egSpec.Name = "nk_flow5_eg"
		egMap, err = ebpf.NewMap(&egSpec)
		if err != nil {
			inMap.Close()
			return fmt.Errorf("create egress flow map: %w", err)
		}
	}

	// 1. TCX ingress program on inDev -> bpf_redirect_peer(nkDev.Index, 0)
	//
	// Equivalent C program:
	//   SEC("tcx/ingress")
	//   int tcx_to_netkit(struct __sk_buff *skb) {
	//       void *data     = (void *)(long)skb->data;
	//       void *data_end = (void *)(long)skb->data_end;
	//       struct ethhdr *eth = data;
	//       if ((void *)(eth + 1) + sizeof(struct iphdr) > data_end)
	//           return TC_ACT_OK;
	//       if (eth->h_proto != bpf_htons(ETH_P_IP))
	//           return TC_ACT_OK;
	//       struct iphdr *iph = (void *)(eth + 1);
	//       if (iph->daddr != pod_ip)
	//           return TC_ACT_OK;
	//       if (FLOW_COUNT_ENABLED)
	//           count_flow5_l2(skb, &nk_flow5_in);
	//       return bpf_redirect_peer(nk_ifindex, 0);
	//   }
	//
	// Use 32-bit JNE.Imm32 comparisons because LoadMem (Word/Half) zero-extends
	// into 64-bit registers while 64-bit JNE.Imm sign-extends int32 immediates
	// (which would mismatch any IPv4 address whose high bit in native order is 1,
	// e.g. last octet >= 128 on little-endian).
	tcxInsns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, skbDataOffset, asm.Word),    // r2 = skb->data
		asm.LoadMem(asm.R3, asm.R1, skbDataEndOffset, asm.Word), // r3 = skb->data_end
		asm.Mov.Reg(asm.R4, asm.R2),                             // r4 = data
		asm.Add.Imm(asm.R4, ethHLen+ipv4HLen),                   // r4 += sizeof(ethhdr) + sizeof(iphdr)
		asm.JGT.Reg(asm.R4, asm.R3, "pass"),                     // if (r4 > data_end) goto pass
		asm.LoadMem(asm.R5, asm.R2, ethProtoOffset, asm.Half),   // r5 = eth->h_proto
		asm.JNE.Imm32(asm.R5, ethPIP, "pass"),                   // if (r5 != htons(ETH_P_IP)) goto pass
		asm.LoadMem(asm.R5, asm.R2, ipv4DaddrOffset, asm.Word),  // r5 = iph->daddr
		asm.JNE.Imm32(asm.R5, podIP, "pass"),                    // if (r5 != pod_ip) goto pass
	}
	if inMap != nil {
		tcxInsns = append(tcxInsns, buildFlowCountInsns(inMap.FD(), ethPIP, true, "do_redirect")...)
	}
	tcxInsns = append(tcxInsns,
		asm.Mov.Imm(asm.R1, int32(nkDev.Index)).WithSymbol("do_redirect"), // r1 = nk_ifindex
		asm.Mov.Imm(asm.R2, 0),            // r2 = 0 (flags)
		asm.FnRedirectPeer.Call(),         // return bpf_redirect_peer(r1, r2)
		asm.Return(),                      //
		asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // pass: return TC_ACT_OK (0)
		asm.Return(),
	)

	tcxProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "tcx_to_netkit",
		Type:         ebpf.SchedCLS,
		Instructions: tcxInsns,
		License:      "GPL",
	})
	if err != nil {
		if inMap != nil {
			inMap.Close()
			egMap.Close()
		}
		return fmt.Errorf("load tcx_to_netkit: %w", err)
	}

	// 2. Netkit peer program on nkDev -> bpf_redirect_neigh(inDev.Index, NULL, 0, 0)
	// Checks skb->protocol so it works identically in both L2 and L3 netkit modes.
	//
	// Equivalent C program:
	//   SEC("netkit/peer")
	//   int nk_from_pod(struct __sk_buff *skb) {
	//       if (skb->protocol != bpf_htons(ETH_P_IP))
	//           return NETKIT_PASS;
	//       if (FLOW_COUNT_ENABLED)
	//           count_flow5_l2_or_l3(skb, &nk_flow5_eg);
	//       return bpf_redirect_neigh(in_ifindex, NULL, 0, 0);
	//   }
	nkInsns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, skbProtocolOffset, asm.Word), // r2 = skb->protocol
		asm.JNE.Imm32(asm.R2, ethPIP, "pass"),                    // if (r2 != htons(ETH_P_IP)) goto pass
	}
	if egMap != nil {
		nkInsns = append(nkInsns, buildFlowCountInsns(egMap.FD(), ethPIP, false, "do_redirect")...)
	}
	nkInsns = append(nkInsns,
		asm.Mov.Imm(asm.R1, int32(inDev.Index)).WithSymbol("do_redirect"), // r1 = in_ifindex
		asm.Mov.Imm(asm.R2, 0),            // r2 = NULL (params)
		asm.Mov.Imm(asm.R3, 0),            // r3 = 0 (plen)
		asm.Mov.Imm(asm.R4, 0),            // r4 = 0 (flags)
		asm.FnRedirectNeigh.Call(),        // return bpf_redirect_neigh(r1, NULL, 0, 0)
		asm.Return(),                      //
		asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // pass: return NETKIT_PASS (0)
		asm.Return(),
	)

	nkProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "nk_from_pod",
		Type:         ebpf.SchedCLS,
		Instructions: nkInsns,
		License:      "GPL",
	})
	if err != nil {
		tcxProg.Close()
		if inMap != nil {
			inMap.Close()
			egMap.Close()
		}
		return fmt.Errorf("load nk_from_pod: %w", err)
	}

	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Interface: inDev.Index,
		Program:   tcxProg,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		tcxProg.Close()
		nkProg.Close()
		if inMap != nil {
			inMap.Close()
			egMap.Close()
		}
		return fmt.Errorf("attach TCX ingress on %s: %w", inDev.Name, err)
	}

	nkLink, err := link.AttachNetkit(link.NetkitOptions{
		Interface: nkDev.Index,
		Program:   nkProg,
		Attach:    ebpf.AttachNetkitPeer,
	})
	if err != nil {
		tcxLink.Close()
		tcxProg.Close()
		nkProg.Close()
		if inMap != nil {
			inMap.Close()
			egMap.Close()
		}
		return fmt.Errorf("attach netkit peer on %s: %w", nkDev.Name, err)
	}

	nkFastpathMu.Lock()
	nkFastpathLinks = []link.Link{tcxLink, nkLink}
	nkFastpathProgs = []*ebpf.Program{tcxProg, nkProg}
	nkIngressFlowMap = inMap
	nkEgressFlowMap = egMap
	nkFastpathDumpPath = flowDumpPath
	nkFastpathMu.Unlock()
	return nil
}

// buildFlowCountInsns emits BPF instructions that parse an IPv4 TCP/UDP 5-tuple
// from skb->data and increment its counter in mapFD (BPF_MAP_TYPE_LRU_HASH).
//
// Equivalent C helper:
//
//	struct netkit_flow_key5 {
//	    __be32 saddr, daddr;
//	    __be16 sport, dport;
//	    __u8   proto, pad[3];
//	};
//
//	static __always_inline void count_flow5(struct __sk_buff *skb, void *map) {
//	    void *data     = (void *)(long)skb->data;
//	    void *data_end = (void *)(long)skb->data_end;
//	    __u8 *iph = data;
//	    if (data + 14 + 20 + 4 <= data_end &&
//	        *(__be16 *)(data + 12) == bpf_htons(ETH_P_IP) &&
//	        *(__u8 *)(data + 14) == 0x45) {
//	        iph = data + 14;
//	    } else if (!l2_only && data + 20 + 4 <= data_end && *(__u8 *)data == 0x45) {
//	        iph = data;
//	    } else {
//	        return;
//	    }
//	    __u8 proto = iph[9];
//	    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
//	        return;
//	    struct netkit_flow_key5 key = {};
//	    key.saddr = *(__be32 *)(iph + 12);
//	    key.daddr = *(__be32 *)(iph + 16);
//	    key.sport = *(__be16 *)(iph + 20);
//	    key.dport = *(__be16 *)(iph + 22);
//	    key.proto = proto;
//	    __u64 *val = bpf_map_lookup_elem(map, &key);
//	    if (val) {
//	        __sync_fetch_and_add(val, 1);
//	    } else {
//	        __u64 init = 1;
//	        bpf_map_update_elem(map, &key, &init, BPF_ANY);
//	    }
//	}
func buildFlowCountInsns(mapFD int, ethPIP int32, l2Only bool, doneLabel string) asm.Instructions {
	l2FailLabel := doneLabel
	if !l2Only {
		l2FailLabel = "try_l3"
	}
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, skbDataOffset, asm.Word),    // r2 = skb->data
		asm.LoadMem(asm.R3, asm.R1, skbDataEndOffset, asm.Word), // r3 = skb->data_end
		asm.Mov.Reg(asm.R4, asm.R2),                             // r4 = data
		asm.Add.Imm(asm.R4, ethHLen+ipv4HLen+l4PortsLen),        // r4 += 14 + 20 + 4
		asm.JGT.Reg(asm.R4, asm.R3, l2FailLabel),                // if (r4 > data_end) goto l2Fail
		asm.LoadMem(asm.R5, asm.R2, ethProtoOffset, asm.Half),   // r5 = eth->h_proto
		asm.JNE.Imm32(asm.R5, ethPIP, l2FailLabel),              // if (r5 != htons(ETH_P_IP)) goto l2Fail
		asm.LoadMem(asm.R5, asm.R2, ethHLen, asm.Byte),          // r5 = *(u8 *)(data + 14)
		asm.JNE.Imm32(asm.R5, 0x45, l2FailLabel),                // if (r5 != 0x45) goto l2Fail
		asm.Add.Imm(asm.R2, ethHLen),                            // r2 = data + 14 (iph)
	}
	if !l2Only {
		insns = append(insns,
			asm.Ja.Label("parse_ip"),
			asm.LoadMem(asm.R2, asm.R1, skbDataOffset, asm.Word).WithSymbol("try_l3"), // r2 = skb->data
			asm.LoadMem(asm.R3, asm.R1, skbDataEndOffset, asm.Word),                   // r3 = skb->data_end
			asm.Mov.Reg(asm.R4, asm.R2),                                               // r4 = data
			asm.Add.Imm(asm.R4, ipv4HLen+l4PortsLen),                                  // r4 += 20 + 4
			asm.JGT.Reg(asm.R4, asm.R3, doneLabel),                                    // if (r4 > data_end) goto done
			asm.LoadMem(asm.R5, asm.R2, 0, asm.Byte),                                  // r5 = *(u8 *)data
			asm.JNE.Imm32(asm.R5, 0x45, doneLabel),                                    // if (r5 != 0x45) goto done
		)
	}
	insns = append(insns,
		asm.LoadMem(asm.R5, asm.R2, 9, asm.Byte).WithSymbol("parse_ip"), // r5 = iph->protocol
		asm.JEq.Imm32(asm.R5, ipprotoTCP, "is_tcp_udp"),                 // if (r5 == IPPROTO_TCP) goto is_tcp_udp
		asm.JNE.Imm32(asm.R5, ipprotoUDP, doneLabel),                    // if (r5 != IPPROTO_UDP) goto done
		asm.LoadMem(asm.R4, asm.R2, 12, asm.Word).WithSymbol("is_tcp_udp"), // r4 = iph->saddr
		asm.StoreMem(asm.R10, -16, asm.R4, asm.Word),                       // key.saddr = r4
		asm.LoadMem(asm.R4, asm.R2, 16, asm.Word),                          // r4 = iph->daddr
		asm.StoreMem(asm.R10, -12, asm.R4, asm.Word),                       // key.daddr = r4
		asm.LoadMem(asm.R4, asm.R2, 20, asm.Word),                          // r4 = *(u32 *)(iph + 20) (sport, dport)
		asm.StoreMem(asm.R10, -8, asm.R4, asm.Word),                        // key.sport_dport = r4
		asm.StoreImm(asm.R10, -4, 0, asm.Word),                             // key.proto_pad = 0
		asm.StoreMem(asm.R10, -4, asm.R5, asm.Byte),                        // key.proto = r5
		asm.LoadMapPtr(asm.R1, mapFD),                                      // r1 = &flow_map
		asm.Mov.Reg(asm.R2, asm.R10),                                       // r2 = fp
		asm.Add.Imm(asm.R2, -16),                                           // r2 = &key
		asm.FnMapLookupElem.Call(),                                         // r0 = bpf_map_lookup_elem(r1, r2)
		asm.JEq.Imm(asm.R0, 0, "init_flow"),                                // if (r0 == NULL) goto init_flow
		asm.Mov.Imm(asm.R1, 1),                                             // r1 = 1
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),                           // __sync_fetch_and_add((u64 *)r0, 1)
		asm.Ja.Label(doneLabel),                                            // goto done
		asm.Mov.Imm(asm.R1, 1).WithSymbol("init_flow"),                     // r1 = 1
		asm.StoreMem(asm.R10, -24, asm.R1, asm.DWord),                      // u64 init = 1
		asm.LoadMapPtr(asm.R1, mapFD),                                      // r1 = &flow_map
		asm.Mov.Reg(asm.R2, asm.R10),                                       // r2 = fp
		asm.Add.Imm(asm.R2, -16),                                           // r2 = &key
		asm.Mov.Reg(asm.R3, asm.R10),                                       // r3 = fp
		asm.Add.Imm(asm.R3, -24),                                           // r3 = &init
		asm.Mov.Imm(asm.R4, 0),                                             // r4 = BPF_ANY
		asm.FnMapUpdateElem.Call(),                                         // bpf_map_update_elem(r1, r2, r3, 0)
	)
	return insns
}

func readFlowEntries(m *ebpf.Map) ([]netkitFlowEntry, error) {
	if m == nil {
		return nil, nil
	}
	entries := []netkitFlowEntry{}
	var k netkitFlowKey5
	var v uint64
	it := m.Iterate()
	for it.Next(&k, &v) {
		var sbuf, dbuf [4]byte
		var spbuf, dpbuf [2]byte
		binary.NativeEndian.PutUint32(sbuf[:], k.Saddr)
		binary.NativeEndian.PutUint32(dbuf[:], k.Daddr)
		binary.NativeEndian.PutUint16(spbuf[:], k.Sport)
		binary.NativeEndian.PutUint16(dpbuf[:], k.Dport)
		entries = append(entries, netkitFlowEntry{
			SrcIP:   net.IP(sbuf[:]).String(),
			DstIP:   net.IP(dbuf[:]).String(),
			SrcPort: binary.BigEndian.Uint16(spbuf[:]),
			DstPort: binary.BigEndian.Uint16(dpbuf[:]),
			Proto:   k.Proto,
			Packets: v,
		})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Proto != entries[j].Proto {
			return entries[i].Proto < entries[j].Proto
		}
		if entries[i].SrcPort != entries[j].SrcPort {
			return entries[i].SrcPort < entries[j].SrcPort
		}
		return entries[i].DstPort < entries[j].DstPort
	})
	return entries, nil
}

func detachNetkitFastpath() {
	nkFastpathMu.Lock()
	defer nkFastpathMu.Unlock()
	if nkFastpathDumpPath != "" && (nkIngressFlowMap != nil || nkEgressFlowMap != nil) {
		inEntries, errIn := readFlowEntries(nkIngressFlowMap)
		egEntries, errEg := readFlowEntries(nkEgressFlowMap)
		if errIn == nil && errEg == nil {
			if data, err := json.Marshal(netkitFlowDump{Ingress: inEntries, Egress: egEntries}); err == nil {
				_ = os.WriteFile(nkFastpathDumpPath, append(data, '\n'), 0o644)
			}
		}
		nkFastpathDumpPath = ""
	}
	for _, l := range nkFastpathLinks {
		_ = l.Close()
	}
	nkFastpathLinks = nil
	for _, p := range nkFastpathProgs {
		_ = p.Close()
	}
	nkFastpathProgs = nil
	if nkIngressFlowMap != nil {
		_ = nkIngressFlowMap.Close()
		nkIngressFlowMap = nil
	}
	if nkEgressFlowMap != nil {
		_ = nkEgressFlowMap.Close()
		nkEgressFlowMap = nil
	}
}
