package xdperf

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdperf/pkg/logger"
	"github.com/takehaya/xdperf/pkg/telemetry"
)

type Config struct {
	LoggerConfig logger.Config

	// From For CLI Flags
	PluginPath       string
	PluginName       string
	PluginLanguage   string
	PluginConfig     string
	PluginConfigPath string

	Sender      bool
	Receiver    bool
	SwapResp    bool
	Device      string
	RxDevice    string // device to attach the receive/count XDP program in client mode; empty = same as Device
	Parallelism int
	Count       uint64        // TX worker frame limit (0 = unspecified)
	PPS         uint64        // 0 = unlimited (max speed)
	Duration    time.Duration // 0 = not specified
	Infinite    bool          // enable infinite mode for maximum throughput
	BatchSize   uint32        // syscall batch size tuning (default: 64)

	DurationCountError error // packet-budget error deferred until the plugin traffic mode is known
	CountFromDuration  bool  // CLI-derived packet budget; ignored by TCP connection repetition

	DebugMode int

	SummaryJSON  string // final statistics JSON file; empty = disabled
	ShowNICStats bool   // show NIC-level statistics (may include other traffic on the same interface)
	WasmCacheDir string // WASM compilation cache directory (empty = default ~/.cache/xdperf/wasm/)
	CPUMode      string // NUMA-aware CPU selection mode (auto/local/balanced/node:N/CPU list)
	XDPMode      string // XDP attach mode (auto/native/generic); auto falls back to generic when native attach fails

	OTLPEndpoint   string        // OTLP gRPC endpoint (host:port). Empty = metrics export disabled
	OTLPInterval   time.Duration // OTLP metrics export interval
	OTLPInsecure   bool          // use plaintext gRPC for OTLP export
	OTLPAttributes string        // extra OTLP resource attributes ("key=value,key=value")

	// TCP responder settings (--tcp-server).
	TCPMSS     int           // payload bytes per segment; 0 = MTU-sized default
	TCPRTO     time.Duration // retransmission timeout
	TCPVlanID  int           // 802.1Q VLAN id; 0 = untagged
	TCPVlanPCP int           // 802.1Q priority
	// TCPFlowReport is a CSV path; at the end of the run every flow's ledger
	// (frames sent, data, retransmissions, frames received, replies) is
	// written there. Empty = no report.
	TCPFlowReport string

	// TCP responder (--tcp-server): the TCP counterpart of --recv --swap-resp.
	// Answers SYN / data / FIN from XDP on one listen port; no kernel socket.
	TCPServer   bool
	TCPListen   string // "[ip]:port"; empty host = any IPv4, "[::]:port" = any IPv6
	TCPMaxConns int    // flow table size (LRU)
	TCPAckEvery int    // ACK every N in-order data segments
	// TCPSweepAfter retires LAST_ACK / SYN_RCVD entries idle for this long;
	// 0 = max(65 * TCPRTO, 2s), longer than any FIN/SYN retransmission gap.
	TCPSweepAfter time.Duration

	Version string // xdperf version (from build info), used as service.version
}

// Normalize fills in config fields derived from user input (the XDPMode
// default and PluginLanguage, parsed from a "<name>.<lang>" PluginName). It is idempotent
// and only mutates the receiver; call it before Validate. Keeping the derivation
// here — rather than hidden inside Validate — makes Validate side-effect-free.
func (c *Config) Normalize() {
	if c.XDPMode == "" {
		c.XDPMode = XDPModeAuto.String()
	}
	// A dedicated RX device only makes sense to count on, so it implies
	// receive mode for a sending client.
	if c.RxDevice != "" && c.Sender {
		c.Receiver = true
	}

	// --tcp-server is a receive-only mode with its own RX program.
	if c.TCPServer {
		c.Receiver = true
		c.Sender = false
	}
	if c.PluginLanguage != "" || c.TCPServer {
		return
	}
	if sp := strings.Split(c.PluginName, "."); len(sp) == 2 {
		c.PluginLanguage = strings.ToLower(sp[1])
	}
}

func (c *Config) Validate() error {
	if c.Device == "" {
		return fmt.Errorf("device is required")
	}
	// RxDevice splits the client's RX attach off the TX device; server mode
	// already has a single device role, so --device is the one to use there.
	if c.RxDevice != "" && !c.Sender {
		return fmt.Errorf("--rx-device is only valid in client mode; use --device in server mode")
	}

	// XDP attach mode applies to both client and server mode.
	if _, err := ParseXDPMode(c.XDPMode); err != nil {
		return err
	}

	// OTLP export applies to both client and server mode, so validate it
	// before the server-mode early return. Other otlp flags are silently
	// ignored when no endpoint is set.
	if c.OTLPEndpoint != "" {
		if c.OTLPInterval <= 0 {
			return fmt.Errorf("--otlp-interval must be positive")
		}
		if _, err := telemetry.ParseAttributes(c.OTLPAttributes); err != nil {
			return fmt.Errorf("invalid --otlp-attributes: %w", err)
		}
	}

	if c.TCPFlowReport != "" && (!c.Sender || c.PluginName == "") {
		return fmt.Errorf("--tcp-flow-report requires TCP flow variants")
	}

	if c.TCPServer {
		return c.validateTCPServer()
	}

	// Server mode (recv only) doesn't require sender-specific validations
	if !c.Sender && c.Receiver {
		return nil
	}

	// Sender-specific validations
	if c.PluginName == "" {
		return fmt.Errorf("plugin name is required")
	}
	if c.Parallelism <= 0 {
		return fmt.Errorf("parallelism must be positive")
	}
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible CPU count: %w", err)
	}
	if c.Parallelism > numCPU {
		return fmt.Errorf("parallelism (%d) exceeds available CPU cores (%d)", c.Parallelism, numCPU)
	}
	if c.Duration < 0 {
		return fmt.Errorf("duration must be non-negative")
	}

	// Infinite mode validation (must be checked before count/duration validation)
	if c.Infinite {
		if !c.Sender {
			return fmt.Errorf("--infinite requires --send to be specified")
		}
		if c.Count <= 0 {
			return fmt.Errorf("--infinite requires --count to be specified (used as packet pool size)")
		}
		if c.Duration > 0 {
			return fmt.Errorf("--infinite cannot be used with --duration")
		}
		// Note: --pps is ignored in infinite mode (always max speed)
	} else {
		// Cannot specify both count and duration
		if c.Count > 0 && c.Duration > 0 {
			return fmt.Errorf("cannot specify both --count and --duration")
		}
	}

	// PluginLanguage is derived by Normalize; if it is still empty here, the
	// PluginName was not in "<name>.<lang>" form (and no language was set).
	// Validate the invariant without mutating.
	if c.PluginLanguage == "" {
		if sp := strings.Split(c.PluginName, "."); len(sp) != 2 {
			return fmt.Errorf("invalid plugin name format, must be <name>.<lang>")
		}
	}

	// parallelism and count check (only when count is specified)
	// count は全体の投げるパケットの数
	// parallelism は並列数
	// なので、 count > 0 の場合は count >= parallelism である必要があります
	if c.Count > 0 && c.Count < uint64(c.Parallelism) {
		return fmt.Errorf("count must be greater than or equal to parallelism")
	}

	return nil
}

// validateTCPServer checks the --tcp-server (XDP TCP responder) flags.
func (c *Config) validateTCPServer() error {
	if c.SwapResp {
		return fmt.Errorf("--tcp-server cannot be combined with --swap-resp")
	}
	if c.RxDevice != "" {
		return fmt.Errorf("--tcp-server uses --device only; --rx-device is not supported")
	}
	if c.Count != 0 || c.Infinite {
		return fmt.Errorf("--tcp-server runs until --duration or a signal; --count/--infinite do not apply")
	}
	if _, _, err := ParseTCPListen(c.TCPListen); err != nil {
		return fmt.Errorf("invalid --tcp-listen: %w", err)
	}
	if c.TCPMaxConns <= 0 || c.TCPMaxConns > 1<<24 {
		return fmt.Errorf("--tcp-max-conns must be in 1..%d", 1<<24)
	}
	if c.TCPAckEvery <= 0 || c.TCPAckEvery > 255 {
		return fmt.Errorf("--tcp-ack-every must be in 1..255")
	}
	if c.TCPRTO <= 0 {
		return fmt.Errorf("--tcp-rto must be positive (it sets how long a half-open or half-closed flow is kept)")
	}
	if c.TCPSweepAfter < 0 {
		return fmt.Errorf("--tcp-sweep-after must be non-negative")
	}
	if c.TCPMSS != 0 && (c.TCPMSS < tcpMinMSS || c.TCPMSS > 65535) {
		return fmt.Errorf("--tcp-mss must be 0 (default) or %d..65535", tcpMinMSS)
	}
	if c.TCPVlanID < 0 || c.TCPVlanID > 4094 {
		return fmt.Errorf("--tcp-vlan-id must be in 0..4094")
	}
	if c.TCPVlanPCP < 0 || c.TCPVlanPCP > 7 {
		return fmt.Errorf("--tcp-vlan-pcp must be in 0..7")
	}
	if c.Duration < 0 {
		return fmt.Errorf("duration must be non-negative")
	}
	return nil
}
