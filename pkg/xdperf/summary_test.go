package xdperf

import (
	"encoding/json"
	"net"
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
			if mode == "client" {
				x.Logger = zap.NewNop()
				x.Device = &net.Interface{Name: "xdperf-summary-missing"}
				x.cfg.ShowNICStats = true
				if _, err := x.readNICStats(); err == nil {
					t.Fatal("missing initial NIC stats accepted")
				}
				if err := x.ShowFinalStats(NICStats{}); err == nil {
					t.Fatal("missing final NIC stats accepted")
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != string(data) {
					t.Fatal("NIC read failure changed the summary file")
				}
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

func TestTCPConnectionSummary(t *testing.T) {
	spec, err := coreelf.LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	stats, err := ebpf.NewMap(spec.Maps["tcp_stats_map"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stats.Close() })
	recs := make([]coreelf.BpfTcpStats, ebpf.MustPossibleCPU())
	for _, tc := range []struct {
		name          string
		flows         int
		final, load   coreelf.BpfTcpStats
		loadTime      time.Duration
		reason        string
		portExhausted bool
		wantCPS       [3]float64
	}{
		{"repeated", 4, coreelf.BpfTcpStats{Started: 1000, Established: 1000, Done: 1000}, coreelf.BpfTcpStats{Started: 1000, Established: 800, Done: 600}, 2 * time.Second, "all flows closed", false, [3]float64{500, 400, 300}},
		{"duration", 4, coreelf.BpfTcpStats{Started: 20, Established: 20, Done: 20}, coreelf.BpfTcpStats{Started: 20, Established: 18, Done: 16}, 2 * time.Second, "duration elapsed", false, [3]float64{10, 9, 8}},
		{"signal", 4, coreelf.BpfTcpStats{Started: 20, Established: 20, Done: 20}, coreelf.BpfTcpStats{Started: 20, Established: 18, Done: 16}, 2 * time.Second, "signal", false, [3]float64{10, 9, 8}},
		{"legacy", 4, coreelf.BpfTcpStats{Started: 4, Established: 4, Done: 4}, coreelf.BpfTcpStats{Started: 4, Established: 4, Done: 4}, 2 * time.Second, "all flows closed", false, [3]float64{2, 2, 2}},
		{"exhausted", 4, coreelf.BpfTcpStats{Started: 6, Established: 6, Done: 6}, coreelf.BpfTcpStats{Started: 6, Established: 4, Done: 2}, 2 * time.Second, "port_exhausted", true, [3]float64{3, 2, 1}},
		{"zero elapsed", 4, coreelf.BpfTcpStats{Started: 1}, coreelf.BpfTcpStats{Started: 1}, 0, "worker stopped", false, [3]float64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := make([]coreelf.BpfTcpStats, len(recs))
			values[len(values)-1] = tc.final
			if err := stats.Put(uint32(0), values); err != nil {
				t.Fatal(err)
			}
			x := &Xdperf{
				Logger: zap.NewNop(), summary: &runSummary{}, mixed: &mixedPlan{flows: tc.flows},
				bpfobjs: &coreelf.BpfObjects{BpfMaps: coreelf.BpfMaps{TcpStatsMap: stats}},
			}
			if _, err := x.showTCPFinalStats(recs, tc.portExhausted); err != nil {
				t.Fatal(err)
			}
			x.showTCPConnectionRates(tc.load, tc.loadTime, 500*time.Millisecond, tc.reason)
			data, err := json.Marshal(x.summary)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				TCP map[string]any `json:"tcp"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]any{
				"flows": float64(tc.flows), "started": float64(tc.final.Started),
				"established": float64(tc.final.Established), "done": float64(tc.final.Done),
				"reason": tc.reason, "port_exhausted": tc.portExhausted,
				"load_seconds": tc.loadTime.Seconds(), "drain_linger_seconds": 0.5,
				"started_cps": tc.wantCPS[0], "established_cps": tc.wantCPS[1], "done_cps": tc.wantCPS[2],
			} {
				if got.TCP[key] != want {
					t.Errorf("%s = %v, want %v", key, got.TCP[key], want)
				}
			}
			// Logging rates without --summary-json must not enable JSON output.
			x.summary = nil
			x.showTCPConnectionRates(tc.load, tc.loadTime, 500*time.Millisecond, tc.reason)
			if x.summary != nil {
				t.Fatal("summary enabled without flag")
			}
		})
	}
}
