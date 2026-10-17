package xdperf

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

var tcpFlowStateNames = map[uint8]string{
	tcpFlowClosed:      "closed",
	tcpFlowSynSent:     "syn_sent",
	tcpFlowEstablished: "established",
	tcpFlowFinWait1:    "fin_wait_1",
	tcpFlowFinWait2:    "fin_wait_2",
	tcpFlowDone:        "done",
	tcpFlowFailed:      "failed",
	tcpFlowSkipped:     "skipped",
}

func tcpFlowStateName(s uint8) string {
	if n, ok := tcpFlowStateNames[s]; ok {
		return n
	}
	return strconv.Itoa(int(s))
}

var tcpFlowReportHeader = []string{
	"flow", "src_port", "state", "tx_pkts", "tx_data", "tx_rtx", "rx_pkts", "rx_replies", "bytes_acked",
}

// writeTCPFlowLedger writes one CSV row per flow. tx_pkts + rx_replies is
// every frame the flow put on the wire; tx_data + tx_rtx are its data
// segments (first transmissions and retransmissions).
func writeTCPFlowLedger(w io.Writer, flows []coreelf.BpfTcpFlow) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(tcpFlowReportHeader); err != nil {
		return err
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	for i, f := range flows {
		row := []string{
			strconv.Itoa(i), strconv.Itoa(int(f.SrcPort)), tcpFlowStateName(f.State),
			u(f.TxPkts), u(f.TxData), u(f.TxRtx), u(f.RxPkts), u(f.RxReplies), u(f.BytesAcked),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// readTCPFlows reads the first n entries of tcp_flow_map.
func (x *Xdperf) readTCPFlows(n int) ([]coreelf.BpfTcpFlow, error) {
	flows := make([]coreelf.BpfTcpFlow, n)
	for i := range flows {
		k := uint32(i)
		if err := x.bpfobjs.TcpFlowMap.Lookup(&k, &flows[i]); err != nil {
			return nil, fmt.Errorf("tcp_flow_map[%d]: %w", i, err)
		}
	}
	return flows, nil
}

// writeTCPFlowReport writes the per-flow ledger to --tcp-flow-report.
func (x *Xdperf) writeTCPFlowReport() error {
	if x.cfg.TCPFlowReport == "" {
		return nil
	}
	flows, err := x.readTCPFlows(x.cfg.TCPFlows)
	if err != nil {
		return err
	}
	f, err := os.Create(x.cfg.TCPFlowReport)
	if err != nil {
		return fmt.Errorf("failed to create flow report: %w", err)
	}
	if err := writeTCPFlowLedger(f, flows); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write flow report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write flow report: %w", err)
	}
	var tx, data, rtx, rx, replies uint64
	for _, fl := range flows {
		tx += fl.TxPkts
		data += fl.TxData
		rtx += fl.TxRtx
		rx += fl.RxPkts
		replies += fl.RxReplies
	}
	x.Logger.Info("tcp flow report written",
		zap.String("path", x.cfg.TCPFlowReport),
		zap.Int("flows", len(flows)),
		zap.Uint64("tx_pkts", tx),
		zap.Uint64("tx_data", data),
		zap.Uint64("tx_rtx", rtx),
		zap.Uint64("rx_pkts", rx),
		zap.Uint64("rx_replies", replies),
	)
	return nil
}
