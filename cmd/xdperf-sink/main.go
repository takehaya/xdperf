// xdperf-sink is a small TCP/UDP receiver that counts connections and bytes.
// It is the measurement endpoint for xdperf's TCP flow plugins on a veth test bed
// and is meant to run unchanged as a backend Pod in a Kubernetes cluster.
//
// It prints a one-line summary every --interval and a final JSON line on
// SIGINT/SIGTERM so a test script can compare its counts with the sender's.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// version can be set at build time with -ldflags "-X main.version=...".
var version = "dev"

type counters struct {
	Accepted   atomic.Uint64 `json:"-"`
	Closed     atomic.Uint64 `json:"-"`
	Bytes      atomic.Uint64 `json:"-"`
	UDPPackets atomic.Uint64 `json:"-"`
	UDPBytes   atomic.Uint64 `json:"-"`
	Responses  atomic.Uint64 `json:"-"`
	RespBytes  atomic.Uint64 `json:"-"`
}

type summary struct {
	Proto      string  `json:"proto"`
	Listen     string  `json:"listen"`
	Accepted   uint64  `json:"accepted"`
	Closed     uint64  `json:"closed"`
	Active     uint64  `json:"active"`
	Bytes      uint64  `json:"bytes"`
	UDPPackets uint64  `json:"udp_packets,omitempty"`
	UDPBytes   uint64  `json:"udp_bytes,omitempty"`
	Responses  uint64  `json:"responses,omitempty"`
	RespBytes  uint64  `json:"response_bytes,omitempty"`
	Seconds    float64 `json:"seconds"`
}

// respondSpec is -respond Q:R: after every Q request bytes, write R bytes.
type respondSpec struct {
	request, response uint64
}

func parseSize(v string) (uint64, error) {
	mult := uint64(1)
	switch {
	case strings.HasSuffix(v, "k"):
		mult, v = 1000, strings.TrimSuffix(v, "k")
	case strings.HasSuffix(v, "m"):
		mult, v = 1000*1000, strings.TrimSuffix(v, "m")
	case strings.HasSuffix(v, "g"):
		mult, v = 1000*1000*1000, strings.TrimSuffix(v, "g")
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > ^uint64(0)/mult {
		return 0, fmt.Errorf("invalid size %q", v)
	}
	return n * mult, nil
}

func parseRespond(v string) (*respondSpec, error) {
	if v == "" {
		return nil, nil
	}
	q, r, ok := strings.Cut(v, ":")
	if !ok {
		return nil, fmt.Errorf("-respond wants Q:R, got %q", v)
	}
	var s respondSpec
	var err error
	if s.request, err = parseSize(q); err != nil {
		return nil, err
	}
	if s.response, err = parseSize(r); err != nil {
		return nil, err
	}
	if s.response == 0 {
		return nil, fmt.Errorf("-respond needs a response size above 0")
	}
	return &s, nil
}

// serveRespond answers each Q-byte request with R bytes until the peer
// closes. Q = 0 sends one response right away, then reads until EOF.
func serveRespond(conn net.Conn, spec *respondSpec, buf []byte, c *counters) {
	resp := make([]byte, min(spec.response, 1<<20))
	write := func() error {
		for left := spec.response; left > 0; {
			n, err := conn.Write(resp[:min(left, uint64(len(resp)))])
			left -= uint64(n)
			c.RespBytes.Add(uint64(n))
			if err != nil {
				return err
			}
		}
		c.Responses.Add(1)
		return nil
	}
	if spec.request == 0 {
		if write() != nil {
			return
		}
	}
	var got uint64
	for {
		n, err := conn.Read(buf)
		c.Bytes.Add(uint64(n))
		if spec.request != 0 {
			// A client that waits for each response never has two
			// requests in one read, but a pipelining one may.
			for got += uint64(n); got >= spec.request; got -= spec.request {
				if write() != nil {
					return
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) || got != 0 {
				log.Printf("connection %s ended with %d of %d request bytes pending: %v", conn.RemoteAddr(), got, spec.request, err)
			}
			return
		}
	}
}

func main() {
	listen := flag.String("listen", ":5201", "address to listen on (host:port)")
	proto := flag.String("proto", "tcp", "tcp, udp or both")
	interval := flag.Duration("interval", time.Second, "stats print interval (0 = disable)")
	readBuf := flag.Int("read-buf", 256*1024, "per-connection read buffer size")
	xdpPassDev := flag.String("xdp-pass-dev", "", "attach a pass-through XDP program to this device (veth test beds only, see comment in source)")
	netkitFastpath := flag.String("netkit-fastpath", "", "attach TCX/netkit redirect fastpath (<ingress-dev>:<netkit-primary-dev>:<pod-ipv4>)")
	netkitFlowDump := flag.String("netkit-flow-dump", "", "enable 5-tuple LRU_HASH flow counters on -netkit-fastpath and dump JSON to this path on exit")
	respond := flag.String("respond", "", "TCP only: answer every Q request bytes with R bytes (Q:R, k/m/g suffixes; Q 0 = send R once on accept)")
	showVersion := flag.Bool("v", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("xdperf-sink", version)
		return
	}
	if *readBuf <= 0 {
		log.Fatalf("invalid -read-buf %d: must be > 0", *readBuf)
	}
	spec, err := parseRespond(*respond)
	if err != nil {
		log.Fatal(err)
	}

	// veth quirk: the peer's XDP_TX frames are queued into this device's
	// xdp_ring, but the kernel only schedules this side's NAPI to drain the
	// ring when an XDP program is attached here (veth_xdp_flush checks
	// rq->xdp_prog, not rq->napi). Without it the last ACK of a connection
	// sits in the ring until unrelated traffic arrives. A trivial XDP_PASS
	// program fixes that without touching the packets. Real NICs do not
	// need this.
	if *xdpPassDev != "" {
		if err := attachXDPPass(*xdpPassDev); err != nil {
			log.Fatalf("attach XDP pass program to %s: %v", *xdpPassDev, err)
		}
		defer detachXDPPass()
	}
	if *netkitFastpath != "" {
		if err := attachNetkitFastpathWithFlows(*netkitFastpath, *netkitFlowDump); err != nil {
			log.Fatalf("attach netkit fastpath (%s): %v", *netkitFastpath, err)
		}
		defer detachNetkitFastpath()
	}

	var c counters
	start := time.Now()
	var wg sync.WaitGroup

	tcpOn := *proto == "tcp" || *proto == "both"
	udpOn := *proto == "udp" || *proto == "both"
	if !tcpOn && !udpOn {
		log.Fatalf("invalid -proto %q", *proto)
	}

	var ln net.Listener
	var uc *net.UDPConn
	if tcpOn {
		ln, err = net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("listen tcp %s: %v", *listen, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				c.Accepted.Add(1)
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer c.Closed.Add(1)
					defer conn.Close()
					buf := make([]byte, *readBuf)
					if spec != nil {
						serveRespond(conn, spec, buf, &c)
						return
					}
					for {
						n, err := conn.Read(buf)
						c.Bytes.Add(uint64(n))
						if err != nil {
							return
						}
					}
				}()
			}
		}()
	}
	if udpOn {
		addr, err := net.ResolveUDPAddr("udp", *listen)
		if err != nil {
			log.Fatalf("resolve udp %s: %v", *listen, err)
		}
		uc, err = net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalf("listen udp %s: %v", *listen, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65536)
			for {
				n, _, err := uc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				c.UDPPackets.Add(1)
				c.UDPBytes.Add(uint64(n))
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	var ticker *time.Ticker
	var tick <-chan time.Time
	if *interval > 0 {
		ticker = time.NewTicker(*interval)
		tick = ticker.C
	}
	var prevBytes uint64
	prevT := start
	fmt.Fprintf(os.Stderr, "xdperf-sink listening on %s (%s)\n", *listen, *proto)
	for {
		select {
		case now := <-tick:
			b := c.Bytes.Load()
			dt := now.Sub(prevT).Seconds()
			gbps := float64(b-prevBytes) * 8 / dt / 1e9
			// Closed first: a connection accepted and closed between the
			// two loads must not make closed exceed accepted.
			closed := c.Closed.Load()
			accepted := c.Accepted.Load()
			fmt.Printf("sink: accepted %d active %d closed %d | %.3f Gbps, %d bytes total", accepted, accepted-closed, closed, gbps, b)
			if udpOn {
				fmt.Printf(" | udp %d pkts %d bytes", c.UDPPackets.Load(), c.UDPBytes.Load())
			}
			if spec != nil {
				fmt.Printf(" | %d responses %d bytes", c.Responses.Load(), c.RespBytes.Load())
			}
			fmt.Println()
			prevBytes = b
			prevT = now
		case <-sig:
			if ticker != nil {
				ticker.Stop()
			}
			if ln != nil {
				ln.Close()
			}
			if uc != nil {
				uc.Close()
			}
			closed := c.Closed.Load() // before Accepted, see above
			s := summary{
				Proto:      *proto,
				Listen:     *listen,
				Accepted:   c.Accepted.Load(),
				Closed:     closed,
				Bytes:      c.Bytes.Load(),
				UDPPackets: c.UDPPackets.Load(),
				UDPBytes:   c.UDPBytes.Load(),
				Responses:  c.Responses.Load(),
				RespBytes:  c.RespBytes.Load(),
				Seconds:    time.Since(start).Seconds(),
			}
			s.Active = s.Accepted - s.Closed
			out, _ := json.Marshal(s)
			fmt.Println(string(out))
			if *xdpPassDev != "" {
				detachXDPPass()
			}
			if *netkitFastpath != "" {
				detachNetkitFastpath()
			}
			// Connections still open are not waited for: the summary is the
			// state at signal time, which is what a test script wants.
			os.Exit(0)
		}
	}
}
