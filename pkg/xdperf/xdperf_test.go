package xdperf

import (
	"math"
	"testing"

	"github.com/takehaya/xdperf/pkg/coreelf"
	"github.com/takehaya/xdperf/pkg/guest"
)

func TestCalculateDiffMapSize(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want uint32
	}{
		{name: "receiver", cfg: Config{Count: math.MaxUint64, Parallelism: 1}, want: 1},
		{name: "worker share", cfg: Config{Sender: true, Count: 101, Parallelism: 3}, want: 34},
		{name: "below cap", cfg: Config{Sender: true, Count: uint64(coreelf.MaxDiffEntries) - 2, Parallelism: 1}, want: coreelf.MaxDiffEntries - 1},
		{name: "at cap", cfg: Config{Sender: true, Count: uint64(coreelf.MaxDiffEntries) - 1, Parallelism: 1}, want: coreelf.MaxDiffEntries},
		{name: "above cap", cfg: Config{Sender: true, Count: uint64(coreelf.MaxDiffEntries), Parallelism: 1}, want: coreelf.MaxDiffEntries},
		{name: "uint32 boundary", cfg: Config{Sender: true, Count: 1 << 32, Parallelism: 1}, want: coreelf.MaxDiffEntries},
		{name: "uint32 truncation regression", cfg: Config{Sender: true, Count: math.MaxUint32 + 7, Parallelism: 1}, want: coreelf.MaxDiffEntries},
		{name: "uint64 limit", cfg: Config{Sender: true, Count: math.MaxUint64, Parallelism: 1}, want: coreelf.MaxDiffEntries},
		{name: "large count with workers", cfg: Config{Sender: true, Count: math.MaxUint64, Parallelism: 3}, want: coreelf.MaxDiffEntries},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateDiffMapSize(tt.cfg, nil); got != tt.want {
				t.Fatalf("diff_map size = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCalculateDiffMapSizeForPlugin(t *testing.T) {
	cfg := Config{Sender: true, Count: 3_000_000, Parallelism: 4}
	for _, tt := range []struct {
		name         string
		templateType guest.GeneratorTemplateType
		variants     []guest.PacketVariant
		want         uint32
	}{
		{name: "TCP-only", templateType: guest.GeneratorTemplateTypeVariable, variants: []guest.PacketVariant{{Kind: "tcp_flow"}, {Kind: "tcp_flow"}}, want: 1},
		{name: "mixed packets", templateType: guest.GeneratorTemplateTypeVariable, variants: []guest.PacketVariant{{Kind: "tcp_flow"}, {Kind: "packet"}}, want: coreelf.MaxDiffEntries},
		{name: "implicit packet", templateType: guest.GeneratorTemplateTypeVariable, variants: []guest.PacketVariant{{}}, want: coreelf.MaxDiffEntries},
		{name: "raw", templateType: guest.GeneratorTemplateTypeRaw, want: coreelf.MaxDiffEntries},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := &guest.GeneratorProcessResponse{TemplateType: tt.templateType, VariablePacketTemplate: guest.PacketVariantSet{Variants: tt.variants}}
			if got := calculateDiffMapSize(cfg, resp); got != tt.want {
				t.Fatalf("diff_map size = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCalculatePacketPoolSize(t *testing.T) {
	tests := []struct {
		name    string
		count   uint64
		workers int
		want    int
	}{
		{name: "below cap", count: 101, workers: 3, want: 101},
		{name: "at cap", count: uint64(coreelf.MaxDiffEntries) * 3, workers: 3, want: int(coreelf.MaxDiffEntries) * 3},
		{name: "above cap", count: uint64(coreelf.MaxDiffEntries)*3 + 1, workers: 3, want: int(coreelf.MaxDiffEntries) * 3},
		{name: "uint32 boundary", count: 1 << 32, workers: 1, want: int(coreelf.MaxDiffEntries)},
		{name: "int64 boundary", count: 1 << 63, workers: 1, want: int(coreelf.MaxDiffEntries)},
		{name: "uint64 limit", count: math.MaxUint64, workers: 3, want: int(coreelf.MaxDiffEntries) * 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculatePacketPoolSize(Config{Count: tt.count, Parallelism: tt.workers}); got != tt.want {
				t.Fatalf("generated pool size = %d, want %d", got, tt.want)
			}
		})
	}
}
