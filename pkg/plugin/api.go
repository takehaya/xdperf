package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero/api"
)

func logFunc(ctx context.Context, mod api.Module, level uint32, msgPtr, msgLen uint32) {
	data, ok := mod.Memory().Read(msgPtr, msgLen)
	if !ok {
		return
	}
	logFuncImpl(level, string(data))
}
func logFuncImpl(level uint32, msg string) {
	fmt.Printf("[PLUGIN] [%d] %s\n", level, msg)
}

func metricFunc(ctx context.Context, mod api.Module, namePtr, nameLen uint32, value float64, timestamp int64) {
	data, ok := mod.Memory().Read(namePtr, nameLen)
	if !ok {
		return
	}
	metricFuncImpl(string(data), value, timestamp)
}

func metricFuncImpl(name string, value float64, timestamp int64) {
	t := parseTimestamp(uint64(timestamp))
	fmt.Printf("[METRIC] %s %.6f time=%s \n",
		name,
		value,
		t.Format(time.RFC3339Nano),
	)
}
func parseTimestamp(ts uint64) time.Time {
	nowNs := time.Now().UnixNano()
	switch {
	case ts > uint64(nowNs/100): // ns order
		return time.Unix(0, int64(ts))
	case ts > uint64(nowNs/100_000): // us order
		return time.Unix(0, int64(ts*1000))
	case ts > uint64(nowNs/100_000_000): // ms order
		return time.Unix(0, int64(ts*1_000_000))
	default: // sec order
		return time.Unix(int64(ts), 0)
	}
}
