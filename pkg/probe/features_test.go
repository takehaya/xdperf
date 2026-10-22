package probe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestSetXDPFeatures(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		features              uint64
		driver, live, offload bool
	}{
		{name: "none"},
		{name: "basic", features: 1, driver: true},
		{name: "ndo_xmit", features: 4, live: true},
		{name: "hw_offload", features: 16, offload: true},
		{name: "veth peer unprepared", features: 1 | 2 | 32, driver: true},
		{name: "veth peer ready", features: 1 | 2 | 4 | 32 | 64, driver: true, live: true},
		{name: "all", features: 127, driver: true, live: true, offload: true},
		{name: "unrelated", features: 2 | 8 | 32 | 64 | 1<<63},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &ProbeResult{CurrentXDPProgID: 42, AttachedMode: "driver"}
			r.setXDPFeatures(tt.features)
			if !r.XDPSupported || !r.XDPGenericMode || r.XDPDriverMode != tt.driver ||
				r.LiveFrameMode != tt.live || r.XDPOffloadMode != tt.offload {
				t.Fatalf("unexpected mapping: %+v", r)
			}
			if r.XDPFeatures == nil || *r.XDPFeatures != tt.features {
				t.Fatalf("raw features = %v, want %d", r.XDPFeatures, tt.features)
			}
			if r.CurrentXDPProgID != 42 || r.AttachedMode != "driver" {
				t.Fatalf("attached program info changed: %+v", r)
			}
		})
	}
}

func TestParseXDPFeatures(t *testing.T) {
	message := func(value []byte) []byte {
		msg := []byte{netdevCmdDevGet, 1, 0, 0}
		msg = append(msg, nl.NewRtAttr(netdevADevIfindex, nl.Uint32Attr(42)).Serialize()...)
		return append(msg, nl.NewRtAttr(netdevADevXDPFeatures, value).Serialize()...)
	}
	value := make([]byte, 8)
	nl.NativeEndian().PutUint64(value, 1<<63|127)
	for _, tt := range []struct {
		name string
		msg  []byte
		want uint64
		err  bool
	}{
		{name: "valid", msg: message(value), want: 1<<63 | 127},
		{name: "zero", msg: message(make([]byte, 8))},
		{name: "short header", msg: []byte{1}, err: true},
		{name: "missing features", msg: make([]byte, nl.SizeofGenlmsg), err: true},
		{name: "short features", msg: message(value[:4]), err: true},
		{name: "invalid attribute", msg: append(make([]byte, nl.SizeofGenlmsg), 3, 0, 3, 0), err: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseXDPFeatures(tt.msg)
			if (err != nil) != tt.err || got != tt.want {
				t.Fatalf("got (%d, %v), want (%d, error=%v)", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestXDPFeaturesJSON(t *testing.T) {
	r := &ProbeResult{}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "xdp_features") {
		t.Fatalf("legacy result includes features: %s", data)
	}
	r.setXDPFeatures(0)
	data, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"xdp_features":0`) {
		t.Fatalf("zero features omitted: %s", data)
	}
}
