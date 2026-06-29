module github.com/takehaya/xdperf/plugins/simpleudp

go 1.25.2

require github.com/takehaya/xdperf/pkg/guest v0.0.0

require (
	github.com/google/gopacket v1.1.19
	github.com/mcuadros/go-defaults v1.2.0 // indirect
)

replace github.com/takehaya/xdperf/pkg/guest => ../../pkg/guest
