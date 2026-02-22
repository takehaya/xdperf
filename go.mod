module github.com/takehaya/xdperf

go 1.26.0

require (
	github.com/cilium/ebpf v0.19.0
	github.com/google/gopacket v1.1.19
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/pkg/errors v0.9.1
	github.com/stealthrocket/wasi-go v0.8.0
	github.com/stealthrocket/wazergo v0.19.1
	github.com/takehaya/xdperf/pkg/guest v0.0.0
	github.com/tetratelabs/wazero v1.9.0
	github.com/urfave/cli v1.22.17
	github.com/vishvananda/netlink v1.3.1
	go.uber.org/zap v1.27.0
	golang.org/x/sys v0.37.0
	golang.org/x/text v0.30.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/mcuadros/go-defaults v1.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.uber.org/multierr v1.10.0 // indirect
)

replace github.com/takehaya/xdperf/pkg/guest => ./pkg/guest

replace github.com/cilium/ebpf => github.com/takehaya/ebpf v0.0.0-20251201163912-684226f5963b
