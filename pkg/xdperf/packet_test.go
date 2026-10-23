package xdperf

import (
	"net"
	"testing"

	"github.com/takehaya/xdperf/pkg/guest"
)

func TestUniformPacketLen(t *testing.T) {
	bases := []BasePacketInfo{
		{Base: guest.BasePacket{Length: 64}},
		{Base: guest.BasePacket{Length: 128}},
	}
	for _, tt := range []struct {
		name    string
		entries []DiffEntry
		want    uint16
	}{
		{name: "empty"},
		{name: "fixed", entries: []DiffEntry{{PacketLen: 64}, {PacketLen: 64}}, want: 64},
		{name: "base fallback", entries: []DiffEntry{{}, {PacketLen: 64}}, want: 64},
		{name: "different bases same target", entries: []DiffEntry{{PacketLen: 64}, {BaseIdx: 1, PacketLen: 64, LenChanged: true}}, want: 64},
		{name: "variable lengths", entries: []DiffEntry{{PacketLen: 64}, {PacketLen: 128}}},
		{name: "variable base lengths", entries: []DiffEntry{{}, {BaseIdx: 1}}},
		{name: "late different length", entries: []DiffEntry{{PacketLen: 64}, {PacketLen: 64}, {PacketLen: 1500}}},
		{name: "below minimum", entries: []DiffEntry{{PacketLen: 63}}},
		{name: "short", entries: []DiffEntry{{PacketLen: 1499}}, want: 1499},
		{name: "default length", entries: []DiffEntry{{PacketLen: 1500}}},
		{name: "long", entries: []DiffEntry{{PacketLen: 1514}}},
		{name: "missing base", entries: []DiffEntry{{BaseIdx: 2, PacketLen: 64}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := uniformPacketLen(bases, tt.entries); got != tt.want {
				t.Fatalf("length = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildSamplePacketLength(t *testing.T) {
	for _, tt := range []struct {
		name   string
		length uint16
		mixed  *mixedPlan
		want   int
	}{
		{name: "default", want: 1500},
		{name: "fixed short", length: 64, want: 64},
		{name: "mixed keeps default", length: 64, mixed: &mixedPlan{}, want: 1500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x := &Xdperf{Device: &net.Interface{HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}, initialPacketLen: tt.length, mixed: tt.mixed}
			packet, err := x.BuildSamplePacket()
			if err != nil {
				t.Fatal(err)
			}
			if len(packet) != tt.want {
				t.Fatalf("length = %d, want %d", len(packet), tt.want)
			}
		})
	}
}
