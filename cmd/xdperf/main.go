package main

import (
	"context"
	"fmt"
	"log"
	"math/bits"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/takehaya/xdperf/pkg/probe"
	"github.com/takehaya/xdperf/pkg/xdperf"
	"github.com/urfave/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	app := newApp(version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "Xdperf"
	app.Version = fmt.Sprintf("%s, %s, %s, %s", version, commit, date, builtBy)

	app.Usage = "high performance XDP based network traffic generator tool"

	app.EnableBashCompletion = true

	// Common flags for the main run command
	runFlags := []cli.Flag{
		cli.StringFlag{
			Name:   "plugin, p",
			EnvVar: "XDPERF_PLUGIN",
			Value:  "simpleudp.tinygo",
			Usage:  "wasm pkt gen plugin file name",
		},
		cli.StringFlag{
			Name:   "plugin-language, L",
			EnvVar: "XDPERF_PLUGIN_LANGUAGE",
			Usage:  "wasm plugin language (go or tinygo etc...)",
		},
		cli.StringFlag{
			Name:   "plugin-path, P",
			EnvVar: "XDPERF_PLUGIN_PATH",
			Value:  "/usr/local/share/xdperf/plugins",
			Usage:  "plugin path, default is /usr/local/share/xdperf/plugins",
		},
		cli.StringFlag{
			Name:   "plugin-config, cfg",
			EnvVar: "XDPERF_PLUGIN_CONFIG",
			Usage:  "plugin configuration (JSON format)",
		},
		cli.StringFlag{
			Name:   "plugin-config-path, cfgpath",
			EnvVar: "XDPERF_PLUGIN_CONFIG_PATH",
			Usage:  "plugin configuration file path (JSON format)",
		},
		cli.BoolTFlag{
			Name:   "send, s",
			EnvVar: "XDPERF_SEND",
			Usage:  "run as send mode",
		},
		cli.BoolFlag{
			Name:   "recv, r",
			EnvVar: "XDPERF_RECV",
			Usage:  "run as receive mode",
		},
		cli.BoolFlag{
			Name:   "swap-resp, swap",
			EnvVar: "XDPERF_SWAP_RESP",
			Usage:  "swap response packets (for echo server)",
		},
		cli.StringFlag{
			Name:     "device, d",
			EnvVar:   "XDPERF_DEVICE",
			Required: true,
			Usage:    "network device name to send packets",
		},
		cli.StringFlag{
			Name:   "rx-device",
			EnvVar: "XDPERF_RX_DEVICE",
			Usage: "device to attach the receive/count XDP program in client mode " +
				"(implies --recv); defaults to --device",
		},
		cli.IntFlag{
			Name:   "parallelism, l",
			EnvVar: "XDPERF_PARALLELISM",
			Value:  1,
			Usage:  "number of parallel packet sending threads",
		},
		cli.StringFlag{
			Name:   "count, c",
			EnvVar: "XDPERF_COUNT",
			Usage: "TX worker frame limit (e.g., 100k, 1m); mixed TCP may finish earlier. " +
				"With --infinite, sets the packet pool size. Finite TCP-only sets may omit count and duration.",
		},
		cli.DurationFlag{
			Name:   "duration, t",
			EnvVar: "XDPERF_DURATION",
			Usage:  "duration to send traffic (e.g., 10s, 1m); with packet variants, --duration requires --pps",
		},
		cli.IntFlag{
			Name:   "debugmode, D",
			EnvVar: "XDPERF_DEBUGMODE",
			Value:  0,
			Usage:  "debug mode level (0: none, 1: on, 2: full verbose)",
		},
		cli.StringFlag{
			Name:   "pps",
			EnvVar: "XDPERF_PPS",
			Usage:  "target packets per second (e.g., 100k, 1m). Empty for max speed",
		},
		cli.BoolFlag{
			Name:   "show-nic-stats",
			EnvVar: "XDPERF_SHOW_NIC_STATS",
			Usage:  "show NIC-level statistics (may include other traffic on the same interface)",
		},
		cli.BoolFlag{
			Name:   "infinite",
			EnvVar: "XDPERF_INFINITE",
			Usage:  "enable infinite mode for maximum throughput. Requires --send args",
		},
		cli.IntFlag{
			Name:   "batch-size",
			EnvVar: "XDPERF_BATCH_SIZE",
			Value:  64,
			Usage:  "syscall batch size tuning (frames per bpf_prog_run in infinite/max-speed mode; 1 to disable batching)",
		},
		cli.StringFlag{
			Name:   "wasm-cache-dir",
			EnvVar: "XDPERF_WASM_CACHE_DIR",
			Usage:  "directory for WASM compilation cache (default: ~/.cache/xdperf/wasm/)",
		},
		cli.StringFlag{
			Name:   "cpu-mode",
			EnvVar: "XDPERF_CPU_MODE",
			Value:  "auto",
			Usage:  "NUMA-aware CPU selection: auto, local, balanced, node:<N>, or CPU list (e.g., 0,2,4,6)",
		},
		cli.StringFlag{
			Name:   "xdp-mode",
			EnvVar: "XDPERF_XDP_MODE",
			Value:  "auto",
			Usage:  "XDP attach mode: auto (fall back to generic when native fails), native, or generic",
		},
		cli.StringFlag{
			Name:   "otlp-endpoint",
			EnvVar: "XDPERF_OTLP_ENDPOINT",
			Usage:  "OTLP gRPC endpoint (host:port, e.g., localhost:4317) to export metrics. Empty to disable",
		},
		cli.DurationFlag{
			Name:   "otlp-interval",
			EnvVar: "XDPERF_OTLP_INTERVAL",
			Value:  10 * time.Second,
			Usage:  "OTLP metrics export interval",
		},
		cli.BoolFlag{
			Name:   "otlp-insecure",
			EnvVar: "XDPERF_OTLP_INSECURE",
			Usage:  "use insecure (plaintext) gRPC connection for OTLP export",
		},
		cli.BoolFlag{
			Name:   "tcp",
			EnvVar: "XDPERF_TCP",
			Usage:  "TCP stream mode: open --tcp-flows connections to --tcp-dst from XDP and stream data; use packet variants for mixed traffic. See docs/ja/design_xdp_tcp.md",
		},
		cli.StringFlag{
			Name:   "tcp-dst",
			EnvVar: "XDPERF_TCP_DST",
			Usage:  "TCP stream destination host:port ([v6]:port for IPv6)",
		},
		cli.StringFlag{
			Name:   "tcp-src-ip",
			EnvVar: "XDPERF_TCP_SRC_IP",
			Usage:  "TCP stream source address (default: the route's preferred source on --device)",
		},
		cli.StringFlag{
			Name:   "tcp-dst-mac",
			EnvVar: "XDPERF_TCP_DST_MAC",
			Usage:  "TCP stream next-hop MAC override (default: ARP/NDP via the kernel neighbor cache)",
		},
		cli.IntFlag{
			Name:   "tcp-flows",
			EnvVar: "XDPERF_TCP_FLOWS",
			Value:  1,
			Usage:  "TCP stream concurrent connections (1..65536)",
		},
		cli.IntFlag{
			Name:   "tcp-port-base",
			EnvVar: "XDPERF_TCP_PORT_BASE",
			Value:  10000,
			Usage:  "TCP stream first source port; flows use port-base..port-base+flows-1",
		},
		cli.IntFlag{
			Name:   "tcp-window",
			EnvVar: "XDPERF_TCP_WINDOW",
			Value:  32,
			Usage:  "TCP stream max segments in flight per flow (fixed window)",
		},
		cli.IntFlag{
			Name:   "tcp-mss",
			EnvVar: "XDPERF_TCP_MSS",
			Usage:  "TCP stream payload bytes per segment, 64..65535 (default: MTU-sized, 1448 for IPv4 / 1428 for IPv6)",
		},
		cli.StringFlag{
			Name:   "tcp-bytes",
			EnvVar: "XDPERF_TCP_BYTES",
			Usage:  "TCP stream bytes to send per flow (e.g. 100m, 1g); 0 = stream until --duration",
		},
		cli.DurationFlag{
			Name:   "tcp-rto",
			EnvVar: "XDPERF_TCP_RTO",
			Value:  200 * time.Millisecond,
			Usage:  "TCP stream retransmission timeout",
		},
		cli.IntFlag{
			Name:   "tcp-vlan-id",
			EnvVar: "XDPERF_TCP_VLAN_ID",
			Usage:  "TCP stream 802.1Q VLAN id (0 = untagged)",
		},
		cli.IntFlag{
			Name:   "tcp-vlan-pcp",
			EnvVar: "XDPERF_TCP_VLAN_PCP",
			Usage:  "TCP stream 802.1Q priority",
		},
		cli.StringFlag{
			Name:   "tcp-ip-id",
			EnvVar: "XDPERF_TCP_IP_ID",
			Value:  "flow",
			Usage:  "TCP stream IPv4 ID: flow (per connection, like Linux: GRO can merge a flow's segments) or shared (one counter per TX CPU: interleaved flows reach the peer unmerged)",
		},
		cli.StringFlag{
			Name:   "tcp-flow-report",
			EnvVar: "XDPERF_TCP_FLOW_REPORT",
			Usage:  "TCP stream or mixed variants: write each TCP flow's ledger (frames sent/received, data segments, retransmissions) to this CSV file at the end",
		},
		cli.BoolFlag{
			Name:   "tcp-server",
			EnvVar: "XDPERF_TCP_SERVER",
			Usage:  "TCP responder mode: answer SYN/data/FIN on --tcp-listen from XDP (no kernel socket, data discarded). Implies --recv",
		},
		cli.StringFlag{
			Name:   "tcp-listen",
			EnvVar: "XDPERF_TCP_LISTEN",
			Value:  ":5201",
			Usage:  "TCP responder listen address [ip]:port (no ip = any IPv4, [::]:port = any IPv6)",
		},
		cli.IntFlag{
			Name:   "tcp-max-conns",
			EnvVar: "XDPERF_TCP_MAX_CONNS",
			Value:  262144,
			Usage:  "TCP responder flow table size (LRU)",
		},
		cli.DurationFlag{
			Name:   "tcp-sweep-after",
			EnvVar: "XDPERF_TCP_SWEEP_AFTER",
			Usage:  "TCP responder: retire half-open / half-closed flows idle this long (0 = max(65*tcp-rto, 2s))",
		},
		cli.IntFlag{
			Name:   "tcp-ack-every",
			EnvVar: "XDPERF_TCP_ACK_EVERY",
			Value:  1,
			Usage:  "TCP responder: ACK every N in-order data segments (PSH/FIN/out-of-order are always acked)",
		},
		cli.StringFlag{
			Name:   "otlp-attributes",
			EnvVar: "XDPERF_OTLP_ATTRIBUTES",
			Usage:  "additional OTLP resource attributes (key=value,key=value)",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run the traffic generator (send or receive mode)",
			Flags:   runFlags,
			Action:  run,
		},
		{
			Name:    "probe",
			Aliases: []string{"p"},
			Usage:   "Probe XDP capabilities of a network device",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "device, d",
					EnvVar:   "XDPERF_DEVICE",
					Required: true,
					Usage:    "network device name to probe",
				},
				cli.BoolFlag{
					Name:   "json, j",
					EnvVar: "XDPERF_JSON",
					Usage:  "output results in JSON format",
				},
			},
			Action: probe.RunProbe,
		},
	}

	return app
}

func ParseArgs(ctx *cli.Context) (xdperf.Config, error) {
	var c xdperf.Config
	// Keep the existing logger-only environment settings. CLI flags resolve
	// their own environment variables so defaults cannot overwrite them.
	err := envconfig.Process("xdperf_loggerconfig", &c.LoggerConfig)
	if err != nil {
		return xdperf.Config{}, fmt.Errorf("config parsing failed: %w", err)
	}
	c.PluginName = ctx.String("plugin")
	c.PluginPath = ctx.String("plugin-path")
	c.PluginConfig = ctx.String("plugin-config")
	c.PluginConfigPath = ctx.String("plugin-config-path")
	c.Sender = ctx.Bool("send")
	c.Receiver = ctx.Bool("recv")
	c.Device = ctx.String("device")
	c.RxDevice = ctx.String("rx-device")
	c.Parallelism = ctx.Int("parallelism")
	c.Duration = ctx.Duration("duration")
	c.DebugMode = ctx.Int("debugmode")
	c.PluginLanguage = ctx.String("plugin-language")
	c.SwapResp = ctx.Bool("swap-resp")
	c.ShowNICStats = ctx.Bool("show-nic-stats")
	c.Infinite = ctx.Bool("infinite")
	c.BatchSize = uint32(ctx.Int("batch-size"))
	c.WasmCacheDir = ctx.String("wasm-cache-dir")
	c.CPUMode = ctx.String("cpu-mode")
	c.XDPMode = ctx.String("xdp-mode")
	c.OTLPEndpoint = ctx.String("otlp-endpoint")
	c.OTLPInterval = ctx.Duration("otlp-interval")
	c.OTLPInsecure = ctx.Bool("otlp-insecure")
	c.OTLPAttributes = ctx.String("otlp-attributes")
	c.Version = version
	c.TCP = ctx.Bool("tcp")
	// The default packet plugin does not apply to standalone TCP.
	if c.TCP && !ctx.IsSet("plugin") && !ctx.IsSet("p") {
		c.PluginName = ""
	}
	c.TCPDst = ctx.String("tcp-dst")
	c.TCPSrcIP = ctx.String("tcp-src-ip")
	c.TCPDstMAC = ctx.String("tcp-dst-mac")
	c.TCPFlows = ctx.Int("tcp-flows")
	c.TCPPortBase = ctx.Int("tcp-port-base")
	c.TCPWindow = ctx.Int("tcp-window")
	c.TCPMSS = ctx.Int("tcp-mss")
	c.TCPRTO = ctx.Duration("tcp-rto")
	c.TCPVlanID = ctx.Int("tcp-vlan-id")
	c.TCPVlanPCP = ctx.Int("tcp-vlan-pcp")
	c.TCPIPID = ctx.String("tcp-ip-id")
	c.TCPFlowReport = ctx.String("tcp-flow-report")
	c.TCPServer = ctx.Bool("tcp-server")
	c.TCPListen = ctx.String("tcp-listen")
	c.TCPMaxConns = ctx.Int("tcp-max-conns")
	c.TCPAckEvery = ctx.Int("tcp-ack-every")
	c.TCPSweepAfter = ctx.Duration("tcp-sweep-after")
	tcpBytes, err := xdperf.ParseCount(ctx.String("tcp-bytes"))
	if err != nil {
		return xdperf.Config{}, fmt.Errorf("invalid --tcp-bytes value: %w", err)
	}
	c.TCPBytes = tcpBytes

	// Parse count
	countStr := ctx.String("count")
	count, err := xdperf.ParseCount(countStr)
	if err != nil {
		return xdperf.Config{}, fmt.Errorf("invalid count value: %w", err)
	}
	c.Count = count

	// Parse PPS
	ppsStr := ctx.String("pps")
	pps, err := xdperf.ParsePPS(ppsStr)
	if err != nil {
		return xdperf.Config{}, fmt.Errorf("invalid PPS value: %w", err)
	}
	c.PPS = pps

	if c.DebugMode > 0 {
		// set verbose logging
		c.LoggerConfig.Verbose = 1
	}

	if c.TCP && c.PluginName != "" {
		return xdperf.Config{}, fmt.Errorf("--tcp cannot be combined with --plugin; use TCP flow variants")
	}

	// Derive computed fields (e.g. PluginLanguage) before validating.
	c.Normalize()

	// Validate config
	if err := c.Validate(); err != nil {
		return xdperf.Config{}, fmt.Errorf("config validation failed: %w", err)
	}

	// Calculate count from duration if specified (after validation)
	// The TCP modes do not use Count: --duration and --pps are applied
	// directly (with fractional per-worker rates).
	tcpMode := c.TCP || c.TCPServer
	if c.Sender && !tcpMode && c.Duration > 0 && c.PPS > 0 {
		// Divide the full 128-bit product to floor the budget exactly, including
		// sub-second durations. Div64 requires hi < divisor for a uint64 result.
		hi, lo := bits.Mul64(c.PPS, uint64(c.Duration))
		if hi >= uint64(time.Second) {
			return xdperf.Config{}, fmt.Errorf("calculated count exceeds uint64 range")
		}
		c.Count, _ = bits.Div64(hi, lo, uint64(time.Second))
		if c.Count == 0 {
			return xdperf.Config{}, fmt.Errorf("calculated count must be greater than zero; increase --pps or --duration")
		}
	}

	// Post-validation: check count >= parallelism after duration calculation
	if c.Sender && !tcpMode && c.Count > 0 && c.Count < uint64(c.Parallelism) {
		return xdperf.Config{}, fmt.Errorf("calculated count (%d) must be greater than or equal to parallelism (%d)", c.Count, c.Parallelism)
	}

	// plugin config load
	if c.PluginConfig == "" && c.PluginConfigPath != "" {
		configData, err := os.ReadFile(c.PluginConfigPath)
		if err != nil {
			return xdperf.Config{}, fmt.Errorf("failed to read plugin config file: %w", err)
		}
		c.PluginConfig = string(configData)
	}
	return c, nil
}

func run(ctx *cli.Context) error {
	c, err := ParseArgs(ctx)
	if err != nil {
		return fmt.Errorf("argument parsing failed: %w", err)
	}
	xdp, err := xdperf.NewXdperf(c)
	if err != nil {
		return fmt.Errorf("xdperf initialization failed: %w", err)
	}
	defer xdp.Close()

	if c.Receiver && !c.Sender {
		err = xdp.StartServer(context.Background())
		if err != nil {
			return fmt.Errorf("xdperf server start failed: %w", err)
		}
		return nil
	}

	err = xdp.StartClient(context.Background())
	if err != nil {
		return fmt.Errorf("xdperf client start failed: %w", err)
	}
	return nil
}
