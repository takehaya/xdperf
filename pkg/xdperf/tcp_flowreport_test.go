package xdperf

import (
	"bytes"
	"testing"

	"github.com/takehaya/xdperf/pkg/coreelf"
)

func TestWriteTCPFlowLedger(t *testing.T) {
	flows := []coreelf.BpfTcpFlow{
		{SrcPort: 20000, State: tcpFlowDone, TxPkts: 102, TxData: 100, RxPkts: 104, RxReplies: 2, BytesAcked: 144800},
		{SrcPort: 20001, State: tcpFlowFailed, TxPkts: 7, RxPkts: 0},
		{SrcPort: 20002, State: 42, TxPkts: 3, TxData: 1, TxRtx: 1},
	}
	var buf bytes.Buffer
	if err := writeTCPFlowLedger(&buf, flows); err != nil {
		t.Fatal(err)
	}
	want := "flow,src_port,state,tx_pkts,tx_data,tx_rtx,rx_pkts,rx_replies,bytes_acked\n" +
		"0,20000,done,102,100,0,104,2,144800\n" +
		"1,20001,failed,7,0,0,0,0,0\n" +
		"2,20002,42,3,1,1,0,0,0\n"
	if got := buf.String(); got != want {
		t.Fatalf("csv =\n%s\nwant\n%s", got, want)
	}
}
