package coreelf

// Request/response rounds on the TCP client (mixed_has_exchange): the flow
// sends bytes_target per round, waits for resp_target bytes, and closes after
// rounds_target rounds.

import (
	"testing"

	"github.com/cilium/ebpf"
)

func xchgStats(t *testing.T, objs *BpfObjects) BpfTcpStats {
	t.Helper()
	n, _ := ebpf.PossibleCPU()
	recs := make([]BpfTcpStats, n)
	if err := objs.TcpStatsMap.Lookup(uint32(0), &recs); err != nil {
		t.Fatal(err)
	}
	var s BpfTcpStats
	for _, r := range recs {
		s.RoundsDone += r.RoundsDone
		s.RespBytes += r.RespBytes
		s.RespTimeouts += r.RespTimeouts
		s.ShortResponses += r.ShortResponses
		s.PeerClosedEarly += r.PeerClosedEarly
		s.Failed += r.Failed
	}
	return s
}

// waiting is a flow with done responses of r bytes received and every
// request it may send so far (min(rounds, done+1) of q bytes) sent and acked.
func waiting(q, r uint64, rounds, done uint32) BpfTcpFlow {
	f := established(0)
	requests := uint64(done + 1)
	if rounds != 0 && requests > uint64(rounds) {
		requests = uint64(rounds)
	}
	sent := q * requests
	f.BytesTarget, f.RespTarget, f.RoundsTarget, f.RoundsDone = q, r, rounds, done
	f.BytesAcked = sent
	f.SndUna, f.SndNxt, f.SndMax = 1+uint32(sent), 1+uint32(sent), 1+uint32(sent)
	f.RxBytes = r * uint64(done)
	f.RcvNxt = 5001 + uint32(f.RxBytes)
	return f
}

// setFlow stores flow 0 (as returned by getFlow, so src_port is kept).
func setFlow(t *testing.T, objs *BpfObjects, f BpfTcpFlow) {
	t.Helper()
	k := uint32(0)
	if err := objs.TcpFlowMap.Put(&k, &f); err != nil {
		t.Fatal(err)
	}
}

func withPayload(s seg, n int) seg {
	s.payloadLen = n
	return s
}

func TestTcpXchgRounds(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := established(0)
	f.BytesTarget, f.RespTarget, f.RoundsTarget = 100, 1000, 2
	frame := setupClient(t, objs, clientOpts{}, f)
	for round := uint32(0); round < 2; round++ {
		seq := 1 + 100*round
		ret, out := txOnce(t, objs, frame)
		if ret != xdpTx {
			t.Fatalf("round %d: request ret = %d", round, ret)
		}
		if d := decode(t, out); d.tcp.Seq != seq || len(d.tcp.Payload) != 100 || d.tcp.FIN {
			t.Fatalf("round %d: request seq %d len %d fin %v", round, d.tcp.Seq, len(d.tcp.Payload), d.tcp.FIN)
		}
		if got := getFlow(t, objs, 0); got.RoundStartNs == 0 {
			t.Fatalf("round %d: round_start_ns not set", round)
		}
		// Nothing more to send and no FIN while the response is pending.
		if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
			t.Fatalf("round %d: sent while waiting: ret = %d", round, ret)
		}
		// The response acks the request and carries R bytes in one segment.
		in := withPayload(fromPeer(false, 0, 5001+1000*round, seq+100, tcpACK|tcpPSH), 1000)
		ret, out = runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in))
		if ret != xdpTx {
			t.Fatalf("round %d: response ret = %d", round, ret)
		}
		if d := decode(t, out); d.tcp.Ack != 5001+1000*(round+1) {
			t.Fatalf("round %d: ack %d", round, d.tcp.Ack)
		}
		if got := getFlow(t, objs, 0); got.RoundsDone != round+1 || got.RxBytes != 1000*uint64(round+1) ||
			got.RoundStartNs != 0 || got.RttSamples != uint64(round+1) {
			t.Fatalf("round %d: rounds_done %d rx_bytes %d start %d samples %d", round, got.RoundsDone, got.RxBytes,
				got.RoundStartNs, got.RttSamples)
		}
	}
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("FIN ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpFIN|tcpACK || d.tcp.Seq != 201 {
		t.Fatalf("want FIN at 201, got flags %#x seq %d", tcpFlags(d.tcp), d.tcp.Seq)
	}
	if s := xchgStats(t, objs); s.RoundsDone != 2 || s.RespBytes != 2000 {
		t.Fatalf("stats rounds %d bytes %d", s.RoundsDone, s.RespBytes)
	}
	if got := getFlow(t, objs, 0); got.RttSamples != 2 || got.RttSumNs == 0 || got.RttMaxNs == 0 || got.RoundStartNs != 0 {
		t.Fatalf("rtt samples %d sum %d max %d start %d", got.RttSamples, got.RttSumNs, got.RttMaxNs, got.RoundStartNs)
	}
}

func TestTcpXchgOneSegmentCompletesSeveralRounds(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := waiting(0, 300, 2, 0) // download: no request
	setupClient(t, objs, clientOpts{}, f)
	in := withPayload(fromPeer(false, 0, 5001, 1, tcpACK), 1000)
	if ret, _ := runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in)); ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if got := getFlow(t, objs, 0); got.RoundsDone != 2 {
		t.Fatalf("rounds_done %d, want capped at 2", got.RoundsDone)
	}
}

func TestTcpXchgDownloadSendsNothing(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := established(0)
	f.BytesTarget, f.RespTarget, f.RoundsTarget = 0, 1000, 1 // 0 is "no request", not unlimited
	frame := setupClient(t, objs, clientOpts{}, f)
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want nothing to send", ret)
	}
}

func TestTcpXchgResponseTimeout(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	// Any VM has been up longer than the timeout, so 1 ns after boot is stale.
	const timeoutMs = 500
	const stale = 1
	now := monoNow(t)
	f := waiting(100, 1000, 1, 0)
	f.LastSendNs = now
	frame := setupClient(t, objs, clientOpts{respTimeoutMs: timeoutMs}, f)
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("before the timeout: ret = %d", ret)
	}
	// Data received recently keeps the flow alive although the request is old.
	got := getFlow(t, objs, 0)
	got.LastSendNs, got.LastRxNs = stale, monoNow(t)
	setFlow(t, objs, got)
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("receiving: ret = %d", ret)
	}
	got.LastRxNs = stale
	setFlow(t, objs, got)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); !d.tcp.RST {
		t.Fatalf("want RST, got flags %#x", tcpFlags(d.tcp))
	}
	if s := xchgStats(t, objs); s.RespTimeouts != 1 || s.Failed != 1 {
		t.Fatalf("resp_timeouts %d failed %d", s.RespTimeouts, s.Failed)
	}
}

func TestTcpXchgPeerFin(t *testing.T) {
	for _, tc := range []struct {
		name         string
		done, rounds uint32
		payload      int
		closeBySrv   bool
		short, early uint64
	}{
		{name: "mid-response", rounds: 1, payload: 500, short: 1},
		{name: "round-boundary", done: 1, rounds: 3, early: 1},
		{name: "after-last-round", done: 1, rounds: 1, closeBySrv: true},
		{name: "over-long-response", done: 1, rounds: 1, payload: 10, closeBySrv: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
			f := waiting(100, 1000, tc.rounds, tc.done)
			frame := setupClient(t, objs, clientOpts{closeByServer: tc.closeBySrv}, f)
			in := withPayload(fromPeer(false, 0, f.RcvNxt, f.SndMax, tcpACK|tcpFIN), tc.payload)
			if ret, _ := runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in)); ret != xdpTx {
				t.Fatalf("ret = %d", ret)
			}
			if s := xchgStats(t, objs); s.ShortResponses != tc.short || s.PeerClosedEarly != tc.early {
				t.Fatalf("short %d early %d", s.ShortResponses, s.PeerClosedEarly)
			}
			// No new request after the peer closed: FIN right away.
			ret, out := txOnce(t, objs, frame)
			if ret != xdpTx {
				t.Fatalf("FIN ret = %d", ret)
			}
			if d := decode(t, out); tcpFlags(d.tcp) != tcpFIN|tcpACK {
				t.Fatalf("flags %#x, want FIN", tcpFlags(d.tcp))
			}
		})
	}
}

func TestTcpXchgCloseByServerWaitsForPeerFin(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := waiting(100, 1000, 1, 1) // last response received
	frame := setupClient(t, objs, clientOpts{closeByServer: true}, f)
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want to wait for the peer FIN", ret)
	}
}

func TestTcpXchgUntilFin(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := waiting(100, 0, 1, 0)
	frame := setupClient(t, objs, clientOpts{untilFin: true}, f)
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want to wait for the response", ret)
	}
	in := withPayload(fromPeer(false, 0, 5001, f.SndMax, tcpACK), 1000)
	runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in))
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want to wait for the FIN", ret)
	}
	runProg(t, objs.XdpRxTcpMixed, buildSeg(t, fromPeer(false, 0, 6001, f.SndMax, tcpACK|tcpFIN)))
	if s := xchgStats(t, objs); s.RoundsDone != 1 || s.ShortResponses != 0 || s.PeerClosedEarly != 0 {
		t.Fatalf("stats %+v", s)
	}
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("FIN ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpFIN|tcpACK {
		t.Fatalf("flags %#x", tcpFlags(d.tcp))
	}
}

func TestTcpXchgFinWait2KeepsReceiving(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := waiting(100, 5000, 1, 0)
	f.State = tfFinWait2
	f.SndUna, f.SndNxt, f.SndMax = f.SndMax+1, f.SndMax+1, f.SndMax+1 // drained: our FIN acked
	f.FinRetries = 6                                                  // at max_fin_retries: the next expiry resets
	f.LastSendNs = 1
	frame := setupClient(t, objs, clientOpts{drain: true, rtoNs: 1_000_000_000}, f)
	in := withPayload(fromPeer(false, 0, 5001, f.SndMax, tcpACK), 1000)
	runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in))
	if got := getFlow(t, objs, 0); got.FinRetries != 0 || got.RxBytes != 1000 || got.LastRxNs == 0 {
		t.Fatalf("fin_retries %d rx_bytes %d last_rx %d", got.FinRetries, got.RxBytes, got.LastRxNs)
	}
	// The probe timer runs from the data, not from our FIN long ago.
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("ret = %d, want no probe and no RST while data flows", ret)
	}
	if got := getFlow(t, objs, 0); got.State != tfFinWait2 {
		t.Fatalf("state %d", got.State)
	}
}

func TestTcpXchgDrainWhileWaiting(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	frame := setupClient(t, objs, clientOpts{drain: true}, waiting(100, 1000, 3, 1))
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpFIN|tcpACK {
		t.Fatalf("flags %#x, want FIN instead of the next request", tcpFlags(d.tcp))
	}
}

// Our FIN went first (drain): the peer's FIN answers it and says nothing
// about the responses.
func TestTcpXchgPeerFinAfterOurFin(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := waiting(100, 1000, 0, 1)
	f.State = tfFinWait2
	f.SndUna, f.SndNxt, f.SndMax = f.SndMax+1, f.SndMax+1, f.SndMax+1
	setupClient(t, objs, clientOpts{}, f)
	in := withPayload(fromPeer(false, 0, f.RcvNxt, f.SndMax, tcpACK|tcpFIN), 300) // mid-response too
	if ret, _ := runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in)); ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if s := xchgStats(t, objs); s.ShortResponses != 0 || s.PeerClosedEarly != 0 {
		t.Fatalf("short %d early %d", s.ShortResponses, s.PeerClosedEarly)
	}
	if got := getFlow(t, objs, 0); got.State != tfDone {
		t.Fatalf("state %d", got.State)
	}
}

// When the response arrives before the whole request is sent, the next
// segment still ends at the request boundary and the next request is timed.
func TestTcpXchgSegmentStopsAtRequestEnd(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	f := established(0)
	f.BytesTarget, f.RespTarget, f.RoundsTarget = 1500, 10, 2
	frame := setupClient(t, objs, clientOpts{}, f)
	if ret, out := txOnce(t, objs, frame); ret != xdpTx || len(decode(t, out).tcp.Payload) != 1000 {
		t.Fatalf("first segment ret %d", ret)
	}
	in := withPayload(fromPeer(false, 0, 5001, 1001, tcpACK), 10)
	runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in))
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); d.tcp.Seq != 1001 || len(d.tcp.Payload) != 500 || !d.tcp.PSH {
		t.Fatalf("seq %d len %d psh %v, want the rest of request 1", d.tcp.Seq, len(d.tcp.Payload), d.tcp.PSH)
	}
	if got := getFlow(t, objs, 0); got.RoundStartNs != 0 {
		t.Fatalf("round timer restarted inside request 1")
	}
	ret, out = txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); d.tcp.Seq != 1501 || len(d.tcp.Payload) != 1000 {
		t.Fatalf("seq %d len %d, want request 2", d.tcp.Seq, len(d.tcp.Payload))
	}
	if got := getFlow(t, objs, 0); got.RoundStartNs == 0 {
		t.Fatalf("request 2 not timed")
	}
}

// A one-way flow in a program built with exchange support keeps the upload
// behavior: bytes_target 0 is unlimited and received data is not counted.
func TestTcpXchgOneWayFlowInExchangeBuild(t *testing.T) {
	objs := loadTCPObjsWith(t, MixedProgramFeatures{Exchange: true})
	frame := setupClient(t, objs, clientOpts{}, established(0))
	if ret, out := txOnce(t, objs, frame); ret != xdpTx || len(decode(t, out).tcp.Payload) != 1000 {
		t.Fatalf("ret %d, want unlimited data", ret)
	}
	in := withPayload(fromPeer(false, 0, 5001, 1, tcpACK), 100)
	runProg(t, objs.XdpRxTcpMixed, buildSeg(t, in))
	if got := getFlow(t, objs, 0); got.RxBytes != 0 || got.RcvNxt != 5101 {
		t.Fatalf("rx_bytes %d rcv_nxt %d", got.RxBytes, got.RcvNxt)
	}
}

// Without the exchange constant the round fields are ignored: the flow is a
// plain upload of bytes_target and sends FIN once it is acked.
func TestTcpXchgOffKeepsUpload(t *testing.T) {
	objs := loadTCPObjs(t)
	f := waiting(100, 1000, 1, 0)
	f.BytesTarget = 100
	frame := setupClient(t, objs, clientOpts{}, f)
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("ret = %d", ret)
	}
	if d := decode(t, out); tcpFlags(d.tcp) != tcpFIN|tcpACK {
		t.Fatalf("flags %#x, want FIN", tcpFlags(d.tcp))
	}
}

// The load-time fallback for old verifiers examines fewer flows per TX
// iteration: idle flows then take more iterations to skip, nothing else changes.
func TestTcpTxReducedScan(t *testing.T) {
	saved := mixedTxScanDivisors
	mixedTxScanDivisors = []uint32{4} // 8 / 4: two flows per iteration
	t.Cleanup(func() { mixedTxScanDivisors = saved })
	objs := loadTCPObjs(t)
	if scan, full := MixedTxScan(); scan != 2 || full != 8 {
		t.Fatalf("scan %d of %d, want 2 of 8", scan, full)
	}
	idle := established(0)
	idle.State = tfFinWait2 // FIN acked, no probe due
	idle.LastSendNs = monoNow(t)
	frame := setupClient(t, objs, clientOpts{}, idle, idle, established(0))
	if ret, _ := txOnce(t, objs, frame); ret != xdpDrop {
		t.Fatalf("first iteration ret %d, want DROP after two idle flows", ret)
	}
	ret, out := txOnce(t, objs, frame)
	if ret != xdpTx {
		t.Fatalf("second iteration ret %d", ret)
	}
	if d := decode(t, out); uint16(d.tcp.SrcPort) != testPortBase+2 || len(d.tcp.Payload) != 1000 {
		t.Fatalf("port %d len %d, want flow 2's data", d.tcp.SrcPort, len(d.tcp.Payload))
	}
}
