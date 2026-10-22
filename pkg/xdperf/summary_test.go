package xdperf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/coreelf"
	"go.uber.org/zap"
)

func TestSummaryJSON(t *testing.T) {
	n := ebpf.MustPossibleCPU()
	newStatsMap := func(value coreelf.BpfDatarec) *ebpf.Map {
		t.Helper()
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 32, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		values := make([]coreelf.BpfDatarec, n)
		values[0] = value
		values[n-1].Packets += 3
		if err := m.Put(uint32(0), values); err != nil {
			t.Fatal(err)
		}
		return m
	}
	tx := newStatsMap(coreelf.BpfDatarec{Packets: 7, Bytes: 1000, DiffErrors: 2, ChecksumErrors: 1})
	rx := newStatsMap(coreelf.BpfDatarec{Packets: 17, Bytes: 2000})
	for _, mode := range []string{"client", "receiver", "tcp", "tcp_server"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "summary.json")
			x := &Xdperf{cfg: Config{SummaryJSON: path, TCPServer: mode == "tcp_server"}, bpfobjs: &coreelf.BpfObjects{BpfMaps: coreelf.BpfMaps{TxStatsMap: tx, RxStatsMap: rx}}}
			x.beginSummary()
			if mode == "tcp" {
				x.summary.TCP = &tcpSummary{Flows: 4, Done: 3, Failed: 1, Retransmits: 5, WindowStalls: 6}
				x.summary.Mixed = &mixedSummary{DispatchErrors: 7, TCPTX: 8, RXInvalidTCP: 9}
			}
			if mode == "tcp_server" {
				x.summary.TCPServer = &tcpServerSummary{Accepted: 4, Closed: 3, Active: 1, Bytes: 4096, BuildErrors: 2}
			}
			if err := x.writeSummary(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			check := func(obj map[string]any, key string, want float64) {
				t.Helper()
				if obj[key] != want {
					t.Errorf("%s = %v, want %v", key, obj[key], want)
				}
			}
			if got["elapsed_seconds"].(float64) <= 0 {
				t.Fatal("missing elapsed time")
			}
			if mode != "tcp_server" {
				for key, want := range map[string]float64{"tx_packets": 10, "tx_bytes": 1000, "rx_packets": 20, "rx_bytes": 2000, "diff_errors": 2, "checksum_errors": 1} {
					check(got, key, want)
				}
				check(got, "tx_pps", 10/got["elapsed_seconds"].(float64))
				check(got, "rx_bps", 16000/got["elapsed_seconds"].(float64))
			} else {
				check(got, "tx_packets", 0)
				for key, want := range map[string]float64{"accepted": 4, "closed": 3, "active": 1, "bytes": 4096, "build_errors": 2} {
					check(got["tcp_server"].(map[string]any), key, want)
				}
			}
			if mode == "tcp" {
				for key, want := range map[string]float64{"flows": 4, "done": 3, "failed": 1, "retransmits": 5, "window_stalls": 6} {
					check(got["tcp"].(map[string]any), key, want)
				}
				check(got["mixed"].(map[string]any), "rx_invalid_tcp", 9)
			} else if _, ok := got["tcp"]; ok {
				t.Fatal("unexpected TCP stats")
			}
			if _, ok := got["nic"]; ok {
				t.Fatal("unexpected NIC stats")
			}
			x.cfg.SummaryJSON = filepath.Join(path, "missing.json")
			if err := x.writeSummary(); err == nil {
				t.Fatal("write failure ignored")
			}
		})
	}
}

func TestSummaryRates(t *testing.T) {
	s := runSummary{TxPackets: 100, TxBytes: 1000, RxPackets: 50, RxBytes: 500}
	s.setRates(2 * time.Second)
	if s.TxPPS != 50 || s.TxBPS != 4000 || s.RxPPS != 25 || s.RxBPS != 2000 {
		t.Fatalf("rates: %+v", s)
	}
	zero := runSummary{}
	zero.setRates(0)
	if _, err := json.Marshal(zero); err != nil {
		t.Fatal(err)
	}
	x := &Xdperf{Logger: zap.NewNop()}
	x.beginSummary()
	if x.summary != nil {
		t.Fatal("summary enabled without flag")
	}
	if err := x.writeSummary(); err != nil {
		t.Fatal(err)
	}
}
