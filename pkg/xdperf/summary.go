package xdperf

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
)

// Packet counters have the same scope as tx_stats_map / rx_stats_map;
// TCP flow and responder counters are reported separately.
type runSummary struct {
	started        time.Time
	ElapsedSeconds float64           `json:"elapsed_seconds"`
	TxPackets      uint64            `json:"tx_packets"`
	TxBytes        uint64            `json:"tx_bytes"`
	RxPackets      uint64            `json:"rx_packets"`
	RxBytes        uint64            `json:"rx_bytes"`
	TxPPS          float64           `json:"tx_pps"`
	TxBPS          float64           `json:"tx_bps"`
	RxPPS          float64           `json:"rx_pps"`
	RxBPS          float64           `json:"rx_bps"`
	DiffErrors     uint64            `json:"diff_errors"`
	ChecksumErrors uint64            `json:"checksum_errors"`
	TCP            *tcpSummary       `json:"tcp,omitempty"`
	TCPServer      *tcpServerSummary `json:"tcp_server,omitempty"`
	Mixed          *mixedSummary     `json:"mixed,omitempty"`
	NIC            *nicSummary       `json:"nic,omitempty"`
}

func (x *Xdperf) beginSummary() {
	if x.cfg.SummaryJSON != "" {
		x.summary = &runSummary{started: time.Now()}
	}
}

func (s *runSummary) setRates(elapsed time.Duration) {
	s.ElapsedSeconds = elapsed.Seconds()
	if s.ElapsedSeconds > 0 {
		s.TxPPS = float64(s.TxPackets) / s.ElapsedSeconds
		s.TxBPS = float64(s.TxBytes) * 8 / s.ElapsedSeconds
		s.RxPPS = float64(s.RxPackets) / s.ElapsedSeconds
		s.RxBPS = float64(s.RxBytes) * 8 / s.ElapsedSeconds
	}
}

func (x *Xdperf) writeSummary() error {
	if x.summary == nil {
		return nil
	}
	s := x.summary
	elapsed := time.Since(s.started)
	// The responder uses tcp_srv_stats_map, not the packet stats maps.
	if !x.cfg.TCPServer {
		recs := make([]coreelf.BpfDatarec, ebpf.MustPossibleCPU())
		var err error
		s.TxPackets, s.TxBytes, s.DiffErrors, s.ChecksumErrors, err = sumStats(x.bpfobjs.TxStatsMap, recs)
		if err != nil {
			return fmt.Errorf("summary JSON TX stats: %w", err)
		}
		s.RxPackets, s.RxBytes, _, _, err = sumStats(x.bpfobjs.RxStatsMap, recs)
		if err != nil {
			return fmt.Errorf("summary JSON RX stats: %w", err)
		}
	}
	s.setRates(elapsed)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode summary JSON: %w", err)
	}
	if err := os.WriteFile(x.cfg.SummaryJSON, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write summary JSON: %w", err)
	}
	return nil
}

type nicSummary struct {
	TxPackets       uint64  `json:"nic_tx_packets"`
	TxDropped       uint64  `json:"nic_tx_dropped"`
	XDPToNICDropped uint64  `json:"xdp_to_nic_dropped"`
	DropRatePercent float64 `json:"drop_rate_percent"`
}

type mixedSummary struct {
	PacketOpportunities uint64  `json:"packet_opportunities"`
	TCPOpportunities    uint64  `json:"tcp_opportunities"`
	PacketTX            uint64  `json:"packet_tx"`
	TCPTX               uint64  `json:"tcp_tx"`
	TCPRXReplies        uint64  `json:"tcp_rx_replies"`
	TCPTXRatio          float64 `json:"tcp_tx_ratio"`
	DispatchErrors      uint64  `json:"dispatch_errors"`
	PacketBytes         uint64  `json:"packet_bytes"`
	PacketErrors        uint64  `json:"packet_errors"`
	PacketRX            uint64  `json:"packet_rx"`
	PacketRXScope       string  `json:"packet_rx_scope"`
	DrainOpportunities  uint64  `json:"drain_opportunities"`
	RXParseFailed       uint64  `json:"rx_parse_failed"`
	RXPortOutside       uint64  `json:"rx_port_outside"`
	RXTupleMismatch     uint64  `json:"rx_tuple_mismatch"`
	RXNeighbor          uint64  `json:"rx_neighbor"`
	RXOther             uint64  `json:"rx_other"`
	RXInvalidTCP        uint64  `json:"rx_invalid_tcp"`
}

type tcpSummary struct {
	Started            uint64  `json:"started"`
	PortExhausted      bool    `json:"port_exhausted"`
	Reason             string  `json:"reason"`
	LoadSeconds        float64 `json:"load_seconds"`
	DrainLingerSeconds float64 `json:"drain_linger_seconds"`
	StartedCPS         float64 `json:"started_cps"`
	EstablishedCPS     float64 `json:"established_cps"`
	DoneCPS            float64 `json:"done_cps"`
	Flows              int     `json:"flows"`
	SynSent            uint64  `json:"syn_sent"`
	Established        uint64  `json:"established"`
	Done               uint64  `json:"done"`
	Failed             uint64  `json:"failed"`
	RstRcvd            uint64  `json:"rst_rcvd"`
	DataSegments       uint64  `json:"data_segments"`
	DataBytesSent      uint64  `json:"data_bytes_sent"`
	BytesAcked         uint64  `json:"bytes_acked"`
	Retransmits        uint64  `json:"retransmits"`
	RetransmitsTimeout uint64  `json:"retransmits_timeout"`
	RetransmitsDupack  uint64  `json:"retransmits_dupack"`
	AcksRcvd           uint64  `json:"acks_rcvd"`
	AcksSent           uint64  `json:"acks_sent"`
	WindowStalls       uint64  `json:"window_stalls"`
	IdleIterations     uint64  `json:"idle_iterations"`
	Unexpected         uint64  `json:"unexpected"`
	BuildErrors        uint64  `json:"build_errors"`
	FailedEstablished  uint64  `json:"failed_established"`
	Skipped            uint64  `json:"skipped"`
	Aborted            uint64  `json:"aborted"`
	RstSent            uint64  `json:"rst_sent"`
	RetransmitGiveups  uint64  `json:"retransmit_giveups"`
	FinWait2Timeouts   uint64  `json:"fin_wait2_timeouts"`
	AckProbes          uint64  `json:"ack_probes"`
	WindowProbes       uint64  `json:"window_probes"`
	ChallengeAcks      uint64  `json:"challenge_acks"`
}

type tcpServerSummary struct {
	SynRcvd             uint64 `json:"syn_rcvd"`
	SynackSent          uint64 `json:"synack_sent"`
	Accepted            uint64 `json:"accepted"`
	Closed              uint64 `json:"closed"`
	ClosedImplicit      uint64 `json:"closed_implicit"`
	SynTimeouts         uint64 `json:"syn_timeouts"`
	Active              uint64 `json:"active"`
	Bytes               uint64 `json:"bytes"`
	DataSegments        uint64 `json:"data_segments"`
	AcksSent            uint64 `json:"acks_sent"`
	DupAcksSent         uint64 `json:"dup_acks_sent"`
	OutOfOrder          uint64 `json:"out_of_order"`
	FinRcvd             uint64 `json:"fin_rcvd"`
	FinSent             uint64 `json:"fin_sent"`
	RstRcvd             uint64 `json:"rst_rcvd"`
	Recycled            uint64 `json:"recycled"`
	RecycledEstablished uint64 `json:"recycled_established"`
	TableFull           uint64 `json:"table_full"`
	Stray               uint64 `json:"stray"`
	RstSent             uint64 `json:"rst_sent"`
	ResetEstablished    uint64 `json:"reset_established"`
	Unexpected          uint64 `json:"unexpected"`
	BadLength           uint64 `json:"bad_length"`
	ChallengeAcks       uint64 `json:"challenge_acks"`
	BuildErrors         uint64 `json:"build_errors"`
}
