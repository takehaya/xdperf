package plugin

import (
	"context"
	"encoding/json"
)

// Plugin はプラグインの基本インターフェース
type Plugin interface {
	// Name はプラグイン名を返す
	Name() string

	// Version はプラグインバージョンを返す
	Version() string

	// Initialize はプラグインを初期化する
	Initialize(ctx context.Context, config []byte) error

	// Cleanup はプラグインのリソースをクリーンアップする
	Cleanup(ctx context.Context) error
}

// GeneratorPlugin はパケットジェネレータープラグインのインターフェース
type GeneratorPlugin interface {
	Plugin

	// GenerateTemplate はパケットテンプレートを生成する
	GenerateTemplate(ctx context.Context, seq uint64, args []byte) (*GeneratorOutput, error)
}

// VerifierPlugin はパケット検証プラグインのインターフェース
type VerifierPlugin interface {
	Plugin

	// VerifyPacket はパケットを検証する
	VerifyPacket(ctx context.Context, input *VerifierInput) (*VerifierOutput, error)

	// GetStats は検証統計を返す
	GetStats(ctx context.Context) (*VerifierStats, error)
}

// GeneratorOutput はジェネレータープラグインの出力
type GeneratorOutput struct {
	Version    string              `json:"version"`
	Template   PacketTemplateData  `json:"template"`
	Metadata   GeneratorMetadata   `json:"metadata"`
	NextPlugin string              `json:"next_plugin,omitempty"`
}

// PacketTemplateData はパケットテンプレートデータ
type PacketTemplateData struct {
	BasePacket BasePacketDef        `json:"base_packet"`
	Layers     []LayerDefinition    `json:"layers"`
	Modifiers  []ModifierDef        `json:"modifiers"`
	Checksums  []ChecksumDef        `json:"checksums"`
	Variables  map[string]Variable  `json:"variables"`
}

// BasePacketDef はベースパケット定義
type BasePacketDef struct {
	Type   string `json:"type"`   // "hex", "base64", "zeros"
	Data   string `json:"data"`
	Length uint16 `json:"length"`
}

// LayerDefinition はレイヤー定義
type LayerDefinition struct {
	Type   string           `json:"type"`   // "ethernet", "ipv4", "tcp", etc.
	Offset uint16           `json:"offset"`
	Length uint16           `json:"length"`
	Fields map[string]Field `json:"fields"`
}

// Field はフィールド定義
type Field struct {
	Name   string      `json:"name"`
	Offset uint16      `json:"offset"`
	Length uint16      `json:"length"`
	Type   string      `json:"type"` // "uint32", "ipv4", "mac", etc.
	Value  interface{} `json:"value"`
	Endian string      `json:"endian,omitempty"` // "big", "little"
}

// ModifierDef はモディファイア定義
type ModifierDef struct {
	Target    ModifierTarget    `json:"target"`
	Operation ModifierOperation `json:"operation"`
	Params    json.RawMessage   `json:"params"`
}

// ModifierTarget はモディファイアのターゲット
type ModifierTarget struct {
	Layer  string  `json:"layer,omitempty"`  // "ipv4", "tcp"
	Field  string  `json:"field,omitempty"`  // "src_ip", "dst_port"
	Offset *uint16 `json:"offset,omitempty"` // 絶対オフセット
	Length *uint16 `json:"length,omitempty"`
}

// ModifierOperation はモディファイアの操作
type ModifierOperation struct {
	Type     string `json:"type"`      // "increment", "random", "range"
	DataType string `json:"data_type"` // "uint32", "ipv4"
}

// ChecksumDef はチェックサム定義
type ChecksumDef struct {
	Layer      string `json:"layer"`       // "ipv4", "tcp", "udp"
	AutoUpdate bool   `json:"auto_update"` // 自動更新
	Algorithm  string `json:"algorithm,omitempty"`
}

// Variable は変数定義
type Variable struct {
	Name    string      `json:"name"`
	Type    string      `json:"type"`  // "counter", "random_seed"
	Value   interface{} `json:"value"`
	Scope   string      `json:"scope"`   // "global", "per_packet"
	Persist bool        `json:"persist"` // 永続化
}

// GeneratorMetadata はジェネレーターのメタデータ
type GeneratorMetadata struct {
	PacketCount uint64      `json:"packet_count"`
	RatePPS     uint64      `json:"rate_pps"`
	IMIX        *IMIXConfig `json:"imix,omitempty"`
	Tags        []string    `json:"tags"`
	Description string      `json:"description,omitempty"`
}

// IMIXConfig はIMIX設定
type IMIXConfig struct {
	Patterns []IMIXPattern `json:"patterns"`
}

// IMIXPattern はIMIXパターン
type IMIXPattern struct {
	Size       uint16 `json:"size"`
	Weight     uint32 `json:"weight"`
	TemplateID string `json:"template_id,omitempty"`
}

// VerifierInput は検証プラグインへの入力
type VerifierInput struct {
	Version  string                `json:"version"`
	Packet   ProcessedPacket       `json:"packet"`
	Context  VerificationContext   `json:"context"`
	Expected ExpectedResults       `json:"expected"`
}

// ProcessedPacket は処理済みパケット
type ProcessedPacket struct {
	Data       []byte             `json:"data"`
	Length     uint16             `json:"length"`
	Timestamp  int64              `json:"timestamp"`
	Sequence   uint64             `json:"sequence"`
	TemplateID string             `json:"template_id"`
	Layers     []LayerDefinition  `json:"layers,omitempty"`
}

// VerificationContext は検証コンテキスト
type VerificationContext struct {
	XDPAction   string                 `json:"xdp_action"`
	ProcessTime uint64                 `json:"process_time"`
	CPUCore     uint32                 `json:"cpu_core"`
	Variables   map[string]interface{} `json:"variables"`
	BPFStats    *BPFStats              `json:"bpf_stats,omitempty"`
}

// BPFStats はBPF統計
type BPFStats struct {
	Instructions uint64 `json:"instructions"`
	Cycles       uint64 `json:"cycles"`
}

// ExpectedResults は期待結果
type ExpectedResults struct {
	Checksums   map[string]bool        `json:"checksums"`
	Fields      map[string]interface{} `json:"fields"`
	Patterns    []Pattern              `json:"patterns"`
	Constraints *Constraints           `json:"constraints,omitempty"`
}

// Pattern はパターンマッチング定義
type Pattern struct {
	Type   string      `json:"type"`   // "exact", "regex", "range"
	Target string      `json:"target"` // "layer.field"
	Value  interface{} `json:"value"`
	Flags  string      `json:"flags,omitempty"`
}

// Constraints は制約条件
type Constraints struct {
	MinLength  *uint16 `json:"min_length,omitempty"`
	MaxLength  *uint16 `json:"max_length,omitempty"`
	LayerCount *uint16 `json:"layer_count,omitempty"`
}

// VerifierOutput は検証プラグインの出力
type VerifierOutput struct {
	Version         string               `json:"version"`
	Result          VerificationResult   `json:"result"`
	Details         []VerificationDetail `json:"details"`
	Stats           VerifierStats        `json:"stats"`
	Recommendations []string             `json:"recommendations,omitempty"`
}

// VerificationResult は検証結果
type VerificationResult struct {
	Valid    bool     `json:"valid"`
	Score    float64  `json:"score"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// VerificationDetail は検証詳細
type VerificationDetail struct {
	Check    string      `json:"check"`
	Result   bool        `json:"result"`
	Expected interface{} `json:"expected"`
	Actual   interface{} `json:"actual"`
	Message  string      `json:"message"`
	Severity string      `json:"severity"` // "error", "warning", "info"
}

// VerifierStats は検証統計
type VerifierStats struct {
	TotalChecks     uint64  `json:"total_checks"`
	Passed          uint64  `json:"passed"`
	Failed          uint64  `json:"failed"`
	Skipped         uint64  `json:"skipped"`
	ExecutionTimeMS float64 `json:"execution_time_ms"`
}

// PluginMetadata はプラグインメタデータ
type PluginMetadata struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Author       string            `json:"author"`
	Description  string            `json:"description"`
	License      string            `json:"license"`
	Type         string            `json:"type"` // "generator", "verifier"
	Capabilities map[string]bool   `json:"capabilities"`
	Requirements map[string]string `json:"requirements"`
}
