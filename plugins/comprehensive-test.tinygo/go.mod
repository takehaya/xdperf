module github.com/takehaya/xdperf/plugins/comprehensive-test

go 1.25.2

require (
    github.com/mcuadros/go-defaults v1.2.0
    github.com/takehaya/xdperf/pkg/guest v0.0.0
)

replace github.com/takehaya/xdperf/pkg/guest => ../../pkg/guest
