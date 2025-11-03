# xdperf WASM Plugin Quick Guide

`simpleudp` (TinyGo) を基にしたpluginの開発方法情報です。

## 目的
ホスト (xdperf) は WASM を読み込み、以下の関数ハンドラを読み出してパケットデータを取得します。
つまり、利用者はプラグインを実装することで所望のパケットを作る Generator を作る事ができます。

## 必須エクスポート
```go
//go:wasmexport plugin_init     // (cfgPtr, cfgLen) -> uint32 (0=OK)
//go:wasmexport plugin_init
func plugin_init(p, l uint32) uint32 { return 0 }
// (inPtr, inLen, outPtr, outCap) -> int32 (>=0:written, <0:error)
//go:wasmexport plugin_process
func plugin_process(inPtr,inLen,outPtr,outCap uint32) int32 { return 0 }
//go:wasmexport plugin_cleanup
func plugin_cleanup() {}
```

実際にパケットを生成してるのが `plugin_process` です。
ホストが WASM メモリへ config / input / 出力バッファを書き込み。プラグイン側はコピーして JSON 生成して書き戻すようになっています。

## ディレクトリ例
```
plugins/simpleudp/
  main.go      // エクスポート + ロジック
  config.go    // Request/Response 定義
  packet.go    // パケット生成
  go.mod       // 独立モジュール
  out/simpleudp.wasm
```

## 主な構造体
`plugin_process` に対してのRequest/Responceの構造が以下に見えます。

```go
// 入力: パケットの生成要求
type GeneratorRequest struct {
  // ユーザー定義
  SrcIP        string `json:"src_ip"`         // 送信元 IPv4
  DstIP        string `json:"dst_ip"`         // 宛先 IPv4
  SrcPort      uint16 `json:"src_port"`
  DstPort      uint16 `json:"dst_port"`
  PayloadSize  int    `json:"payload_size"`    // 生成するペイロード長

  // 必須
  Count        uint64 `json:"count"`           // 要求テンプレート数 (simpleudp は 1 固定扱い)
  DeviceMacAddr []byte `json:"device_mac_addr"` // ホストが注入 (送信元 MAC)
}

// テンプレート中のパケット本体
type BasePacket struct {
  Data   []byte `json:"data"`   // Ethernet 先頭からの生バイト列 (base64 で JSON 化)
  Length uint16 `json:"length"` // 有効長
}

// 出力: simpleudp は配列 []GeneratorResponse を返す
// 全て必須
type GeneratorResponse struct {
  Template struct {
    BasePacket BasePacket `json:"base_packet"`
  } `json:"template"`
  Metadata struct {
    PacketCount uint64   `json:"packet_count"` // 生成パケット数 (通常 1)
    RatePPS     uint64   `json:"rate_pps"`     // 生成率 (未設定なら 0)
    Tags        []string `json:"tags"`
  } `json:"metadata"`
}
```
`plugin_process` は `[]GeneratorResponse` (配列) を JSON で返却。

## ホスト import
いくつかの便利機能をhostから関数exportをしているのでSDK的に利用する事が可能です。
### log&metric
```go
//go:wasmimport env host_log
func host_log(level, ptr, size uint32)
//go:wasmimport env host_report_metric
func host_report_metric(namePtr uint32, nameLen uint32, value float64, timestamp int64)
```
ラッパで `StringToPtr` を使いログ出力。`level: 0=DEBUG 1=INFO 2=WARN 3=ERROR`

## ビルド (TinyGo)
```bash
cd plugins/simpleudp
tinygo build -scheduler=none -target=wasip1 -buildmode=c-shared -o out/simpleudp.wasm .
```
フラグ要点: `-target=wasip1` / `-buildmode=c-shared` / `-scheduler=none`。

Makefile 例:
```make
plugin-simpleudp:
	cd plugins/simpleudp && tinygo build -scheduler=none -target=wasip1 -buildmode=c-shared -o out/simpleudp.wasm .
```

## メモリヘルパ (例)
```go
func BytesFrom(ptr, size uint32) []byte { return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size) }
func PtrToString(ptr, size uint32) string { return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size) }
func StringToPtr(s string) (uint32, uint32) { p := unsafe.Pointer(unsafe.StringData(s)); return uint32(uintptr(p)), uint32(len(s)) }
```
`runtime.KeepAlive` でライフタイム保持を忘れずに実装してください。

