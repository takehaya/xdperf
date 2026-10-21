# C の共有ヘッダから Go プラグイン用の定義を生成する設計

状態: 段階1〜5を実装済み。
段階6の実際の Cilium Datapath Plugin での確認も、x86_64 ホスト、当該観測実装 `DPP_MODE=6`、IPv4/UDP の VXLAN、skb フックの範囲で完了（Cilium v1.20.3、詳細は11.2節）。
再確認日: 2026-10-21。
以下の前提調査と方式比較は実装前の main 7b16bbc に基づく記録である。
現在は `cmd/packetdefs-gen` と manifest、guest の生成物、Go VXLAN の移行、専用 CI を実装済みであり、末尾に結果を示す。
段階1〜5の実装記録に加え、11.2節に段階6の確認結果を追記した。
実装前にこの設計書を 6c92c5f でコミットし、末尾に実装と検証の記録を追記した。

## 1. 目的と共有の範囲

C の共有ヘッダを正として、Go 製 Wasm プラグインが使う型、整数定数、フィールド位置、バイト列との変換コードを生成する。
生成側と観測側が別々にヘッダ長やオフセットを記述する箇所を減らし、定義の変更を CI で検出できるようにする。
最初の対象は `plugins/vxlan.c/vxlan_shared.h` と `plugins/vxlan.go` とする。

**共有定義**は、C の型に加えて、どの型をパケット上のデータとして扱い、どの数値フィールドをネットワークバイト順で格納するかを明示した規約から成る。
C の `uint16` 相当の型や BTF の整数型だけから、通信上のバイト順やフィールドの意味は判定できない。
したがって、C を正とする範囲と、生成器に与える意味上の指定を分ける。

| 情報 | 正とする場所 |
|---|---|
| フィールドの名前、順序、幅、配列長、構造体のサイズ | C ヘッダを指定ターゲット向けにコンパイルした結果 |
| ポート番号、フラグ、固定長などの整数定数 | C ヘッダ。マクロの式の評価も C コンパイラに任せる |
| 生成対象、Go 名、wire 型か内部キー型か、整数の格納順 | 生成用 manifest。C の意味上の規約と対応づける |
| VNI の取得や設定、入力検査、チェックサム、フローの選択 | C または Go の実装。型生成だけでは共有されない |

パケット生成プラグインとホストの JSON 契約は継続して使う。
共有型を Wasm の線形メモリから Go ホストや BPF マップへ直接渡す ABI は追加しない。

## 2. 実装前に確認した前提

### 2.1 確認した実装

| 対象 | 確認内容 |
|---|---|
| [C の共有ヘッダ](../../plugins/vxlan.c/vxlan_shared.h) | 組み込み整数型の typedef、`#define`、`vxlan_hdr`、`vx_inner_key`、4つの inline 関数 |
| [C プラグイン](../../plugins/vxlan.c/main.c)、[Makefile](../../plugins/vxlan.c/Makefile)、[README](../../plugins/vxlan.c/README.md) | libc と WASI を使わない wasm32 ビルド、JSON の直接入出力、VXLAN の組み立て |
| [Go プラグイン](../../plugins/vxlan.go/main.go)、[設定](../../plugins/vxlan.go/config.go)、[builder](../../plugins/vxlan.go/builder/builder.go) | goshim、Variable テンプレート、独立した VXLAN 定義、VNI 差分、VLAN、IMIX |
| [guest SDK](../../pkg/guest/surface.go)、[goshim](../../pkg/guest/goshim/goshim.go) | JSON 型、Go 版の host import による要求と応答 |
| [plugin manager](../../pkg/plugin/manager.go)、[Go 用 adapter](../../pkg/plugin/goshim.go) | 言語指定が `go` の場合の分岐、他言語のバッファ ABI、export の取得 |
| [既存の型生成指定](../../pkg/coreelf/elf.go)、[生成済み型](../../pkg/coreelf/bpf_bpfel.go) | bpf2go、BTF 由来の型、eBPF ローダー、埋め込みオブジェクト |
| [ルート go.mod](../../go.mod)、[guest go.mod](../../pkg/guest/go.mod)、[VXLAN go.mod](../../plugins/vxlan.go/go.mod) | モジュールの境界、Go バージョン、cilium/ebpf の replace |
| [ルート Makefile](../../Makefile)、[Dockerfile.bpf](../../Dockerfile.bpf) | Go/TinyGo のビルドと Docker 経由の BPF 再生成 |
| [BPF 生成 CI](../../.github/workflows/bpf_generate.yaml)、[テスト CI](../../.github/workflows/test.yaml) | 再生成後の自動コミット、ルートモジュールのテスト、プラグインのビルド |
| [Go 統合テスト](../../pkg/plugin/vxlan_integration_test.go)、[C 統合テスト](../../pkg/plugin/vxlanc_integration_test.go)、[builder テスト](../../plugins/vxlan.go/builder/builder_test.go) | 現行の検証範囲と、Wasm 成果物がない場合の skip |

ライブラリの挙動は、ルート `go.mod` の replace 先である `github.com/takehaya/ebpf` のリビジョン `684226f5963b` のローカルモジュールキャッシュでも確認した。
対象は `cmd/bpf2go/main.go`、`cmd/bpf2go/gen/output.tpl`、`btf/format.go`、`btf/types.go` である。
公開ドキュメントだけから、最新版の API が現在の依存先にもあると仮定しない。

### 2.2 背景との相違と補足

指定された C プラグインは、実装開始時点にも存在した。
作業ブランチは当時の `feat/c-to-go-defs` で、開始時点の HEAD は `origin/main` の 7b16bbc と一致した。
この節は移行前の実装を記録しており、現在の builder は生成済み codec と定数を使う。

- Go、TinyGo、C は同じ JSON 型を使うが、受け渡し方は同一ではない。
  Go 版は `pkg/guest/goshim` を通して要求と応答を host import で交換し、export の4引数は実質的に使わない。
  C 版と TinyGo 版は入力ポインタ、入力長、出力ポインタ、出力容量を使い、戻り値で JSON の長さを返す。
  manager は `malloc/free` も取得して検査する。
- C 版は `--target=wasm32 -nostdlib -ffreestanding` でビルドする。
  Go 版の `GOOS=wasip1 GOARCH=wasm` とは異なり、C 版自体は WASI を必要としない。
  TinyGo の既存サンプルには `import "C"` があるが、これは標準 Go の wasip1 に cgo が使えることを意味しない。
- 共有ヘッダは `memcpy` を使わず、`vx_load16/vx_load32` がバイト読み出しとシフトで big-endian の数値を返す。
  C の `main.c` には独自の `memcpy/memset` があり、ヘッダの制約とプラグイン全体の制約を区別する必要がある。
  Cilium による置き換えの問題は [C 版 README](../../plugins/vxlan.c/README.md) に記載があるが、この前提調査では外部 Datapath Plugin のソースやロード失敗を再検証していない（後の段階6で確認、11.2節）。
- `vxlan_hdr` は `flags`、予約領域、3バイトの VNI、末尾の予約領域を持つ。
  `packed` 指定も C のビットフィールドもなく、すべて1バイト型なので、ソースから期待するサイズは8バイト、アラインメントは1である。
  この値はビルドで実測した結果ではなく、実装時に検証する期待値である。
- `vx_inner_key` は IPv4 アドレス2つ、ポート2つ、32ビットの VNI を持つ内部キーであり、そのままパケット上に現れるヘッダではない。
  ソースから期待するサイズは16バイトで、各フィールドの開始位置は順に 0、4、8、10、12 バイトである。
  コメントは network byte order とする一方、`vxlan_vni` や `vx_load*` は数値を組み立てて返す。
  C プラグインにはこのキーを組み立てる処理がないため、この前提調査では外部観測側での格納順は未確認である（後の段階6で確認、11.2節）。
- Go 版の builder は VXLAN ヘッダを手で8バイトに書き込み、ポート4789、フラグ `0x08`、VNI の位置4を別々に定義している。
  `main.go` の VNI sweep は、3バイト書き込みが Diff で使えないため、VNI の1バイト前の予約領域から4バイトを更新する。
- C 版も Go 版も Variable テンプレートを返すが、設定項目と機能は異なる。
  C 版は固定の外側ヘッダと内側ポート範囲を中心とし、Go 版は VLAN、IMIX、内側 IP、外側ポート、L2-only などを扱う。
- ルートモジュールは Go 1.25.5、guest と Go 版 VXLAN は Go 1.25.2 を指定する。
  ルートの cilium/ebpf は表記上 v0.19.0 だが fork へ置き換えられる。
  guest は独立モジュールであり、ルートの `go test ./...` だけでは guest やプラグイン内のテストを網羅しない。
- 既存の `go:generate` は `-type` を指定せず、マップなどに使う型を bpf2go の既定動作で生成している。
  生成済み Go は `structs.HostLayout` と明示的な padding を含むが、同じファイルに eBPF の import とローダーも含む。
- ルート Makefile には C プラグイン対象のビルドルールが存在する。
  clang または wasm-ld がない場合はスキップするため、照合 CI では C 版の成果物の存在を検査する。

## 3. 方式の比較

### 3.1 共有できる情報

BTF は型とレイアウトの情報を持ち、ソースのプリプロセッサ定義や関数の実装を復元する形式ではない。
構造体のサイズ、メンバーのビットオフセット、enum 値、関数の型情報などを区別して扱う必要がある。
形式上の根拠は [Linux の BTF 仕様](https://docs.kernel.org/bpf/btf.html)を参照する。

| 方式 | 構造体のレイアウト | enum | `#define` | ビットフィールド | 関数 |
|---|---|---|---|---|---|
| bpf2go の `-type` | BTF に残った型から Go 宣言を生成。通常の整数と配列に適する。Go メモリ上で packed を再現する保証は別途必要 | 指定した enum から型と定数を生成できる | BTF にないので直接は不可。enum などへの橋渡しが必要 | 現依存先の formatter は領域を padding として扱い、名前付きアクセスは生成しない | 実装を Go へ変換しない。ローダーが生成されても C 関数を Go から呼べるようにはならない |
| BTF から専用生成器 | サイズとオフセットを使って Go の型、メタデータ、codec を生成できる。出力形式を選べる | 値、幅、符号を読んで生成可能 | enum への橋渡しなどが必要 | ビット位置と幅は取得可能。getter/setter は独自実装が必要 | シグネチャを取得できても関数本体は変換できない |
| ホストで `cgo -godefs` | C コンパイラが認識する型を Go 宣言へ変換。対象 ABI と Go で表現できるレイアウトに制約 | Go 側で参照する値を生成可能 | C 側の評価結果を取得できるものがある。任意のマクロ全体を自動移植するものではない | Go で表現できないフィールドは省略や padding になる | 関数本体は共有できない |
| clang の AST とレイアウト API | C の属性、レコードのサイズ、オフセット、アラインメントを取得可能 | 定数式を C の意味で評価できる | プリプロセッサの収集と定数式の評価を別途組み合わせる。通常の AST だけで全マクロを取得できるわけではない | AST から幅と位置を取り、独自の変換を設計できる | 本体の AST を読めるが、正しい Go 変換器は別の大きな開発になる |
| DWARF から生成 | clang の非 BPF ターゲットでもデバッグ型情報から抽出できる | デバッグ情報に残る値を取得できる | 通常の型情報には残らず、別経路が必要 | 情報の表現差を吸収して独自実装 | 本体の共有にはならない |
| TinyGo の C 連携、C のまま Wasm 化 | C コンパイラの型と関数を利用 | C として利用 | C として利用 | C として利用できるがターゲット ABI に依存 | 対応するツールチェーンなら同じ C の実装を利用できる |

いずれの型生成方式でも、ポインタ先の所有権、可変長データ、union の選択条件、フィールドの意味を型情報だけで決定することはできない。
単純な正規表現によるヘッダ解析は、typedef、条件付きコンパイル、属性、定数式を C と同じ意味で処理できないため採用候補から外す。
別の IDL から C と Go を生成する方法もあるが、今回の「既存 C ヘッダを正とする」という条件を変更するため、将来の比較対象にとどめる。

### 3.2 bpf2go の `-type` を使う場合

最小の検証では、共有ヘッダを include する専用 C 翻訳単位を作り、`-type vxlan_hdr -type vx_inner_key` を渡す。
`-type` は BTF 内の既存の名前を選ぶ指定であり、include しただけの未使用型をコンパイラに保持させる指定ではない。
型を持つ外部リンケージの変数などを置き、コンパイル後の BTF に対象型が存在することを検査する。
指定型を追加する機能は [bpf2go のドキュメント](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go#section-readme)にも記載されている。

ただし、現在の依存先に「型だけを出力する」専用オプションはない。
`-no-global-types` はマップなどからの型の自動選択を止めるもので、ローダーや ELF の埋め込みを消す指定ではない。
出力から型宣言を Go AST で抽出して別ファイルにする方法は可能だが、enum 定数、import、padding、ターゲット別の build tag も処理対象になる。
最終的に必要な専用処理を考えると、BTF から直接、限定した生成物を出す方が責務を明示しやすい。

既存の `pkg/coreelf` を guest から import する案は採用しない。
型の利用だけで eBPF ローダーやホスト用依存を guest に持ち込むためである。
生成済み `bpf_bpfel.go` に `wasm` の build tag が含まれることだけを、Wasm 互換性の根拠にしない。

### 3.3 C ヘッダを直接処理する場合

標準 Go の wasip1 ビルドでは cgo を使えないが、生成専用のホスト環境で `cgo -godefs` を使い、純 Go の成果物をコミットする構成は候補になる。
生成時に cgo を使うことと、配布する Wasm が cgo を必要とすることは別である。
ただし、ホスト ABI から生成した宣言が wasm32 や BPF と一致するかを検証する必要があり、codec と定数選択の設計も残る。
`-godefs` と Go で表現できない C フィールドの扱いは [cgo の公式文書](https://pkg.go.dev/cmd/cgo)を参照する。

clang を直接使う案は、マクロや属性の扱いが増えた場合に有力である。
AST の構造と式に加え、レイアウト API とプリプロセッサ API を使う設計になる。
clang の利用方法は [Clang AST の公式説明](https://clang.llvm.org/docs/IntroductionToTheClangAST.html)を参照する。
CLI の AST JSON やレイアウトダンプを読む方式は libclang の実行時依存を避けられる一方、出力形式のバージョン差を固定とテストで管理する必要がある。

## 4. 推奨する構成

共有ヘッダを clang で BTF 付き ELF に変換し、`cilium/ebpf/btf` を使う小さな専用生成器で、純 Go の型と codec を生成する方式を推奨する。
最初から C 全般を扱う変換器を作らず、固定幅整数、固定長配列、名前付きの平坦な構造体、定数の橋渡し用整数 enum に対象を絞る。
既存の bpf2go は、初期の抽出可能性の検証と比較に使い、guest 向けの最終成果物の形式には依存させない。

この選択には、次の理由がある。

1. 現行プロジェクトで使う BTF 読み出しライブラリを、生成時だけ利用できる。
2. ゲストには標準ライブラリだけを使うコードを配布でき、Go と TinyGo の両方で検証できる。
3. packed の有無にかかわらず、C のフィールドオフセットを使ってバイト列を読み書きできる。
4. wire 型と内部キー型を区別し、バイト順が未指定の型を誤って serialize することを防げる。
5. 非対応の型を黙って省略する動作を避け、対象フィールドのパスを示して生成を失敗させられる。

生成の流れは次のとおりとする。

```text
C の共有ヘッダ + 生成対象と格納順を指定する manifest
  → 生成器が一時 C 翻訳単位を作成
  → clang -target bpfel -g -O2 -c ...
  → ELF 内の .BTF を btf.LoadSpec で読み出す
  → 対象型と定数を検査し、サイズとオフセットを正規化
  → 純 Go の型、定数、codec、レイアウト記録を生成
  → bpfeb と wasm32 でも C のレイアウトを照合
```

`btf.LoadSpec` や `Spec.TypeByName` を使う処理は ELF を読むだけで、カーネルへのロードを必要としない。
API の概要は [btf パッケージ](https://pkg.go.dev/github.com/cilium/ebpf/btf)で確認できる。
生成器はホスト用のコマンドとして実行し、guest モジュールにはこの依存を追加しない。

現依存先の `btf.GoFormatter` は enum 定数や padding を生成できるが、ビットフィールドを省略し、union は最初のメンバーで代表させる。
そのまま呼ぶだけでは本計画の入力検査と codec の契約を満たさない。
専用生成器は BTF のメンバーを検査してから、限定した Go 宣言と codec を出す。

## 5. 生成物と入力規約

### 5.1 Go の型と C のレイアウト

Go 側はフィールドを扱うための値型とし、C 上のメモリ配置は別の定数として生成する。
公開 API は次の形とする。

```go
// Code generated by packetdefs-gen; DO NOT EDIT.
package vxlan

type Header struct {
    Flags uint8
    Rsvd0 [3]uint8
    VNI   [3]uint8
    Rsvd1 uint8
}

type InnerKey struct {
    Saddr uint32
    Daddr uint32
    Sport uint16
    Dport uint16
    VNI   uint32
}

const (
    HeaderSize      = 8
    HeaderVNIOffset = 4
    HeaderVNISize   = 3
    UDPPort         = 4789
    FlagVNI         = 0x08
)

func (h Header) MarshalTo(dst []byte) error
func (h *Header) UnmarshalFrom(src []byte) error
```

この例の数値は現行ヘッダから期待する生成結果であり、実装で手入力する値ではない。
`InnerKey` にも C のサイズと各フィールドのオフセットを生成するが、初回は変換メソッドを付けない。
段階6で外部観測側の格納順は BPF を実行するホストのバイト順と確認したが、今回も codec やマップのキーとして直接渡す API は追加しない。

Go の `unsafe.Sizeof` や `unsafe.Offsetof` が C と一致することは、値型の公開契約にしない。
`structs.HostLayout` を付けても、任意の packed 構造体を Go のメモリ上で再現できる保証にはならない。
このため、バイト列から構造体への unsafe cast や、構造体のメモリ全体を送信する処理は使わない。

### 5.2 エンディアンと整数の意味

wire 型の多バイト整数は、Go 内では通常の整数値として保持し、codec が `encoding/binary.BigEndian` で読み書きする。
`[N]uint8` のフィールドはそのままコピーする。
VNI は現行 C 型に合わせて `[3]uint8` を維持するため、汎用 codec はその3バイトを並べるだけにする。

Go の `NewHeader(vni)`、`VNIValue()` などの補助関数は、初回は手書きの小さな実装にする。
生成したフラグ、配列長、上限値を使い、`vxlan_set_vni/vxlan_vni` と同じ有効値の範囲で照合する。
C の setter は大きな値の上位ビットを落とすが、Go の既存プラグインは範囲外を拒否する。
Go の入力検査は継続し、関数の振る舞いまで自動生成で一致させたとは記述しない。

生成に使う `bpfel` の little-endian は、ELF や C の整数オブジェクトの表現であり、通信上のネットワークバイト順とは区別する。
`bpfeb` でもヘッダ位置や定数が一致することを検査し、Go の codec はホストのバイト順に依存させない。
`__be16` のような typedef があっても、生成器が明示的に意味を割り当てない限り、自動的な big-endian 変換の根拠にしない。

`vx_inner_key` は wire 型として登録しない。
当初は観測側の代入処理と格納順を未確認としていたが、段階6では読み出し関数の戻り値をそのまま BPF を実行するホストのバイト順で格納すると確認した（11.2節）。
将来 codec を追加する場合は、パケットの codec と別に、対象 BPF マップの格納形式を扱うものとして設計する。
別の観測実装に適用する場合も代入処理を確認し、IPv4 アドレス `192.0.2.1` と VNI `0x010203` など、逆順を見分けられる値で照合する。

### 5.3 packed、padding、アラインメント

初期の生成器は、非ビットフィールドの packed 構造体も、BTF にサイズとバイト境界のオフセットがあれば codec の入力にできる設計とする。
たとえば `uint8` の直後に `uint32` がオフセット1で現れる場合も、Go のフィールドをそのアドレスに配置せず、codec が `dst[1:5]` を扱う。
ただし、最初の公開版での packed 対応は、この不整列配置の fixture に合格することを条件とする。

BTF は明示的な `packed` 属性や `alignof` の一般的な取得源としては使わず、得られるサイズと位置を codec の根拠にする。
C のアラインメントは、一時翻訳単位で `__alignof__` を整数 enum に橋渡しして記録する。
レイアウト記録には C のサイズ、アラインメント、各フィールドのオフセットと幅を残す。

wire 型で C の暗黙 padding が発生した場合は、初期版では生成を失敗させ、ヘッダで予約バイトを明示する修正を求める。
通信上の予約フィールドと C コンパイラが挿入する padding は別のものだからである。
予約フィールドは通常のフィールドとしてコピーし、汎用 codec が勝手に0へ書き換えない。
通常の VXLAN 生成では補助コンストラクタが予約フィールドを0で初期化する。
内部キー型の padding はレイアウト記録に残し、将来格納用 codec を作る場合に全体を0で初期化する規約を定める。

### 5.4 Marshal と Unmarshal

固定長 wire 型には `MarshalTo` と `UnmarshalFrom` を生成する。
初期版では、呼び出し側が用意した領域を使い、メソッド内で新しいバッファを確保しない API を主にする。

- 長さが型サイズ未満ならエラーを返し、書き込み先や receiver を変更しない。
- 十分な長さがあれば先頭の型サイズだけを扱い、後続の payload は変更しない。
- コピー前に範囲を検査し、多バイト整数は指定順で読み書きする。
- Unmarshal は値をコピーし、元バッファを保持しない。
- 構造上の読み出しと、フラグや予約値のプロトコル上の妥当性検査は分ける。

`MarshalBinary/UnmarshalBinary` への対応は、実際の呼び出し側が必要とする段階で追加する。
`encoding/binary.Write` で構造体全体を処理するだけの実装は、C の padding や packed の位置を自動的に反映しないため採用しない。

### 5.5 定数とマクロ

現在の `vxlan_shared.h` の整数定数はすべて `#define` であり、そのままでは BTF に残らない。
既存の型とマクロを維持し、manifest に列挙した整数定数を一時 C 翻訳単位で enum に橋渡しする。
VNI 上限の重複解消のための `VX_VNI_MAX` の追加は7.1節に従う。
たとえば、生成器が次のような宣言を作る。

```c
#include "plugins/vxlan.c/vxlan_shared.h"

enum xdperf_vx_constants {
    XD_VX_PORT = VXLAN_UDP_PORT,
    XD_VX_FLAG = VXLAN_FLAG_VNI,
    XD_VX_OUTER_LEN = VX_OUTER_LEN,
};

struct vxlan_hdr xdperf_keep_header;
struct vx_inner_key xdperf_keep_key;
enum xdperf_vx_constants xdperf_keep_constants;
```

値や式を Go 側に複写せず、C コンパイラに評価させる。
`VX_OUTER_LEN` のような式マクロも評価結果を共有できる。
実際の翻訳単位では、他の長さ定数とアラインメントの橋渡し enum も保持し、BTF への残存を検査する。
不足した型や enum があれば成功扱いにしない。

長期的には、プリプロセッサで使わない整数定数を、共有ヘッダ内の名前付き enum に置く規約を候補とする。
ただし、外部利用者が `#if` や `#ifdef` で参照するマクロを単純に enum に置き換えると互換性が壊れる。
外部利用を確認するまでは既存マクロを残し、一時翻訳単位での橋渡しを使う。

初期版で橋渡しする定数は、VXLAN で必要な32ビット符号付き整数の範囲に限定する。
大きな符号なし値や64ビット値は、値の幅と符号を保持する enum/BTF の対応を確認してから拡張する。
式マクロの符号や変換も含めた値を検査し、範囲外を切り詰めて出力しない。
文字列、関数形式マクロ、ポインタ値、型を引数にするマクロは初期対象外とする。

Go 側では、サイズやオフセットに使う定数は型なし整数を基本とする。
名前付き enum を公開する場合は C の幅と符号に対応した Go の整数型と定数を生成する。
Go の名前へ変換した際の衝突、予約語、同名の typedef と struct は明示的な名前対応で解決し、未指定ならエラーにする。

### 5.6 初期版で拒否する型

初期版は、ビットフィールド、union、匿名集成体、ポインタ、関数ポインタ、可変長配列、再帰型、浮動小数点を拒否する。
固定幅を保証できない `long`、`size_t`、ポインタ幅依存の型も共有定義では使わない規約とする。
BTF で typedef を解決した結果だけで起源を判断できない場合があるため、ABI 間の照合も併用する。

ビットフィールドが必要なプロトコルでは、まず C ヘッダを固定幅の整数やバイト配列とマスク定数で表現する。
初期版で名前付きビットフィールドを捨てて生成を続ける動作は採らない。
将来 getter/setter を生成する場合は、C ABI のビット配置と通信上のビット位置を区別した仕様を先に追加する。

## 6. リポジトリへの組み込み

### 6.1 配置とモジュール境界

次の配置を採用する。
この節のファイルは実装済みである。

| 置き場所 | 役割 |
|---|---|
| `plugins/vxlan.c/vxlan_shared.h` | 当初の正本。外部 include のパスを保つ |
| `cmd/packetdefs-gen/` | ルートモジュールのホスト用生成コマンド。BTF 依存はここから利用する |
| `internal/packetdefs/generate.go` | 生成対象の登録と `go:generate` |
| `internal/packetdefs/vxlan/manifest.json` | C の型名と Go 名、定数の選択、型の用途、格納順 |
| `pkg/guest/packetdefs/vxlan/types_gen.go` | 生成された値型、定数、レイアウト情報 |
| `pkg/guest/packetdefs/vxlan/codec_gen.go` | 生成された wire 型の読み書き |
| `pkg/guest/packetdefs/vxlan/helpers.go` | VNI の補助関数。C 関数との対応を記載 |
| `pkg/guest/packetdefs/vxlan/layout_gen.json` | 正規化したレイアウト、入力の識別情報、生成器の形式バージョン |

生成器は manifest から一時ディレクトリに C の翻訳単位と ELF を作成し、検証後に Go を出力する。
一時 ELF を配布物として guest に埋め込まない。
manifest 内の入力パスと出力パスはリポジトリルート基準とし、コマンドには基準ディレクトリを明示する。

生成物を `pkg/guest` の独立したサブパッケージに置くことで、各 Go プラグインの既存の guest 依存から import できる。
このサブパッケージは `guest` 本体や `goshim` を import せず、ホスト上のテストからも利用できるようにする。
プラグインごとに生成型を複製すると、同じヘッダの別世代が残りやすいため、今回の VXLAN では共通の1パッケージとする。
外部プロジェクト固有のヘッダを扱う場合は、同じ生成器を使って各プラグインのモジュール内へ出力する運用も可能にする。

将来、正本を `include/xdperf/packetdefs/` などへ移す場合は、旧パスのヘッダを include だけの互換ラッパーにする。
外部利用者の移行前に正本を移動したり、同じ定義を2つのヘッダへ複製したりしない。

### 6.2 go:generate と Makefile

生成指定はルートモジュール側に置く。
guest 内で生成器を `go run` して、guest の `go.mod` に cilium/ebpf を追加する構成は避ける。
`internal/packetdefs/generate.go` から次を実行する。

```go
//go:generate go run ../../cmd/packetdefs-gen -repo ../.. -manifest internal/packetdefs/vxlan/manifest.json
```

`make packetdefs-gen` は、この登録パッケージに対する `go generate` を実行する。
`make packetdefs-check` は、同じ生成処理を一時ディレクトリへ出力し、コミット済み生成物と比較する。
`make build` や通常の `make vxlan.go` は生成を暗黙に実行せず、コミット済みの純 Go コードを使う。
生成に必要な clang の不足と、一般利用者の Wasm ビルドを分離できる。

`make bpf-gen` は引き続き `pkg/coreelf` の再生成に使う。
パケット定義生成のために `src/xdp_prog.c` を変更したり、本番 BPF マップへ型保持用の変数を追加したりしない。
生成用の C コードは専用の一時翻訳単位に閉じ込める。

### 6.3 ツールチェーンと生成物の管理

Go の生成ファイルとレイアウト記録はコミットする。
通常の Go 製プラグインのビルドでは clang、libclang、cgo、BTF ライブラリを必要としない。
再生成用には BPF と wasm32 のターゲットを持つ clang を用意し、コンパイラ、Go、依存モジュールを固定する。
型抽出だけなら wasm-ld は不要で、C プラグイン自体の Wasm ビルドと照合するジョブには wasm-ld が必要になる。

現行 `Dockerfile.bpf` は LLVM 22 を指定する一方、ベースイメージは可変タグである。
専用の `Dockerfile.packetdefs` で Ubuntu 26.04 と Go 1.25.5 のイメージ digest、および clang-22 と lld-22 のパッケージ版を固定する。
既存の BPF 生成環境は変更しない。
補助パッケージの apt リポジトリ全体は snapshot 化していないため、環境全体の完全な再現を保証するものではない。
ルートモジュールの replace も含む依存固定を使い、生成器だけに最新版の cilium/ebpf を無条件で導入しない。

生成物には日時、絶対パス、一時ディレクトリ名を含めない。
型と定数の並び順を固定し、Go の整形後の内容が再実行で変わらないようにする。
入力の識別情報には共有ヘッダと推移的な include を展開したプリプロセス結果の SHA-256、manifest の SHA-256、生成器の形式バージョンを含め、環境の固定情報も追跡できるようにする。
ハッシュだけの一致を正しさの判定にせず、再生成した内容と意味上の照合を併用する。

### 6.4 CI でのずれの検出

新しいチェックは PR と main への push で実行し、古い生成物が残っていたら失敗させる。
現行の BPF 生成 CI のような自動コミットを、整合性判定の代わりには使わない。
以下は専用 CI `.github/workflows/packetdefs.yaml` で実行する検証である。

1. 固定した環境で生成し直し、期待するファイルの集合と全内容をコミット済み生成物と比較する。
   追加、削除、余分な生成ファイルも検出し、作業ツリーを上書きせず差分を出す。
2. 正規化した BTF から得たサイズ、オフセット、幅、符号、定数を、`bpfel` と `bpfeb` の間で比較する。
   ELF 全体の一致は要求しない。
3. BTF から得た期待値を使う `_Static_assert` を自動生成し、`sizeof`、`__builtin_offsetof`、`__alignof__`、定数値を wasm32 向けにもコンパイルして照合する。
   BPF と wasm32 の条件付きコンパイルや ABI 差を検出し、レイアウトが異なる型は初期版では拒否する。
4. guest モジュールと Go 版 VXLAN モジュールを明示してテストする。
   ルートのテストだけで済ませない。
5. Go wasip1 と TinyGo の小さな利用例をビルドし、wazero 上で同じ既知のヘッダを読み書きさせる。
   クロスビルド成功だけを動作確認とは扱わない。

CI は、共有ヘッダ、manifest、生成器、生成物、依存ファイル、生成コンテナの変更で起動する。
対象が少ない初期は、この軽量ジョブを全 PR で実行する方が、推移的 include の path filter 漏れを避けやすい。
Wasm 統合テストは成果物がないと skip する既存動作に注意し、専用ジョブでは Go 版と C 版を明示的にビルドして存在を確認する。

## 7. VXLAN への最初の適用

### 7.1 ヘッダと型の取り込み

まず、現行 `vxlan_shared.h` を正本として、`vxlan_hdr`、`vx_inner_key`、既存の整数マクロを manifest に登録する。
ヘッダの include パス、組み込み型だけで使える性質、`vx_load16/vx_load32` の実装を維持する。
型生成の都合でヘッダへ libc や Linux 専用の include を加えない。

VNI 上限 `0xFFFFFF` は、現在 C の `main.c` と Go 側に個別に存在する。
移行段階で `VX_VNI_MAX` などの共有定数を正本に追加し、C 版の入力検査と Go 版の入力検査が生成された同じ値を参照する形に揃える。
その変更を含めて、外部利用者のコンパイル互換性を確認する。
既存の長さ定数と `sizeof(struct vxlan_hdr)` が矛盾しないことも C の静的検査に含める。

### 7.2 Go builder と設定の置き換え

Go プラグインは `pkg/guest/packetdefs/vxlan` を import し、次の順に置き換える。

1. builder の VXLAN ポート、フラグ、長さ、VNI 上限を生成定数へ置き換える。
   Ethernet、IPv4、UDP の固定長についても、共有ヘッダ由来の長さとの一致を検証し、重複した数値を持たないようにする。
2. `buildVXLANHeader` を、補助関数で `Header` を作って `MarshalTo` する処理へ変更する。
   バッファ確保は現在の builder の責務とし、生成 codec へ移さない。
3. `vxlan.vni` の位置を `vxlanStart + HeaderVNIOffset` から求める。
   VNI sweep はその1バイト前から4バイトを更新する現行方式を維持する。
   VNI が3バイトで、直前の予約領域を0のまま含められる配置を検査し、条件が変わったら生成またはテストを失敗させる。
4. `VX_OUTER_LEN` は VLAN なし、IPv4 options なしの値であることを明示して使う。
   VLAN ありでは4バイトを加算し、L2-only では存在しない内側 IP/UDP のオフセットを作らない。
5. 設定の `default:"4789"` にも対応する。
   Go の struct tag には const を埋め込めないため、`UnmarshalJSON` で生成定数をデコード前に設定する。
   現在の defaults 設定後のデコードと同様に、省略と null は既定値を維持し、明示的な0は0を保持する。
   ポインタ型だけでは省略と null の現在の動作を再現するための追加処理が必要になるため、この方式を選ぶ。
   JSON のフィールド名と数値の形式は維持し、省略、`null`、明示的な0、任意ポートの現在の挙動をテストで固定する。
   単に0を未指定と判定する実装で、明示した0の意味を変えない。

gopacket による外側と内側の Ethernet/IPv4/UDP 生成、チェックサム指定、IMIX の重み、host import、JSON 応答は既存の責務として残す。
共有ヘッダはフレーム全体の構造やチェックサムを記述していないため、その生成まで自動化したものとは扱わない。
`InnerKey` は Go 版 VXLAN の送信処理では必要がないため、型の生成だけを確認し、形式合わせのために送信処理へ組み込まない。

### 7.3 C 版との役割分担

Go 版は、共有された型と定数を使いながら、既存の SDK や gopacket と組み合わせて生成ロジックを書く選択肢とする。
同じ C の関数本体まで生成側と観測側で使いたい場合は、C 版プラグインを利用する。
標準 Go の wasip1 から inline C 関数を直接呼ぶ仕組みは今回の計画に含めない。

TinyGo の C 連携を使う別構成も考えられるが、標準 Go と同じ仕組みとして説明しない。
C の別 Wasm モジュールを Go から呼ぶ方式も、import 設計、メモリ、ポインタの受け渡しが新たに必要になるため、型共有の初期解には採用しない。

両 VXLAN プラグインを同じ設定体系や同じ機能集合に揃える作業は別とする。
照合時は、同じ VNI の8バイトの VXLAN ヘッダや、共通条件のフィールドを比較する。
MAC、payload、IMIX、チェックサム方針が異なる現行のフレーム全体について、無条件にバイト一致を要求しない。

## 8. 段階的な実装計画と完了条件

以下の各段階ではコードの変更と検証を行う。
実装後に結果を記録する。
外部 Cilium のソースと環境が必要な条件は、ローカルの単体検証とは別に記録する。

| 段階 | 作業 | 完了条件（段階1〜5の結果は11.1節、段階6の結果は11.2節） |
|---|---|---|
| 1. 抽出の成立確認 | 専用翻訳単位に2つの構造体と定数 enum を保持する。bpf2go の `-type` と BTF の読み出しで比較する | ヘッダは8バイト、VNI はオフセット4で3バイト、キーは期待する16バイトの配置になり、式マクロを含む対象定数を取得できる。対象を保持し忘れるケースがエラーになる |
| 2. 限定した生成器 | manifest、純 Go 型、定数、codec、レイアウト記録、非対応型の診断を実装する | 再実行して同じ内容を生成する。通常の整数、配列、packed の不整列配置を正しく encode/decode し、ビットフィールドや union などを拒否する。範囲外定数と名前衝突も失敗する |
| 3. ゲストでの利用 | guest サブパッケージ、VNI 補助関数、Go/TinyGo の利用 fixture を追加する | clang のない通常ビルドで生成済みコードを使え、wazero 上で Go/TinyGo の結果が既知のバイト列に一致する。guest に eBPF や生成器の依存が入らない |
| 4. Go 版 VXLAN の移行 | builder、VNI sweep、設定の既定値を置き換え、共有 VNI 上限を C 版にも適用する | VLAN、L2-only、IMIX、内側チェックサムの on/off、各 sweep、入力エラーの既存仕様が維持される。手書きの VXLAN 長、フラグ、VNI 位置、ポート既定値の重複を解消する |
| 5. CI と配布規約 | 再生成チェック、複数 ABI の検査、モジュール別テスト、固定コンテナを追加する | ヘッダ、式マクロ、配列長、manifest を変更して生成を省いた PR が失敗する。余分な生成ファイルも検出し、正常な再生成後に通る |
| 6. 外部観測側との接続確認 | 共有ヘッダの版を固定し、実際の Cilium Datapath Plugin でコンパイルとロードを確認する | 同じ版のヘッダで生成した Go 版トラフィックを観測でき、内側 tuple と VNI が期待値に一致する。共有ヘッダに関する `memcpy` の問題が再発していないことを対象環境で確認する |

第1段階で BTF の型保持や定数の取得が固定ツールチェーンで安定しない場合は、clang AST とレイアウト API の案へ切り替える判断を行う。
その場合も、純 Go の出力、バイト順の指定、明示 codec、CI の比較という公開契約は維持する。

### 8.1 変換の検証データ

codec の往復だけでは、Marshal と Unmarshal が同じ誤りを持つ場合に検出できない。
C の関数、独立した既知のバイト列、既存の decoder を組み合わせる。

- VNI は 0、1、`0x010203`、`0xFFFFFF` を使う。
  `0x010203` のヘッダが `08 00 00 00 01 02 03 00` になることを、C の `vxlan_set_vni` と Go の両方で確認する。
- 数値フィールドを持つ生成器の fixture には `0x1234`、`0x01020304` を使い、BigEndian の期待値と比較する。
  `vxlan_hdr` だけでは、多バイト整数の変換の誤りを検証できない。
- サイズ不足のすべての入力長でエラーになり、余分な領域が変更されないことを確認する。
  予約フィールドが非0の読み書きも確認し、汎用 codec と正常パケット用コンストラクタを区別する。
- Go builder の既存テストと gopacket の decode を残す。
  統合テストでは VNI sweep の4バイト範囲と予約バイトの維持を確認する。
- C の保持用変数の削除、対象マクロの欠落、符号の不一致、wire 型への暗黙 padding の追加など、生成が失敗すべき入力も用意する。

これらの定義生成と codec のテストは、カーネルへの BPF ロードや root 権限を必要としない。
実際の送信経路や Cilium でのロード確認は、権限が必要な後段の検証として分ける。

## 9. リスクと未決事項

| 論点 | 初期方針と判断に必要な情報 |
|---|---|
| BTF に残らない意味 | wire/内部キーの分類とバイト順を manifest に必須指定する。型名やコメントだけから推測しない |
| `vx_inner_key` の格納順とヘッダコメント | 格納順は段階6で確認済み。`vx_load32` / `vx_load16` と `vxlan_vni` で数値化して代入したキーは BPF を実行するホストのバイト順（検証した x86_64 ではリトルエンディアン）。Go からこの外部マップと交換する場合も同じ順序で扱う。型とレイアウトのみの生成を維持し、codec は追加しない。誤った `network byte order` コメントは、固定ハッシュと生成物を更新する次のヘッダ改版で修正する（11.2節） |
| 型と enum の除去 | 専用翻訳単位で実体を持つ変数から参照し、コンパイル後に存在を検査する。`-type` やデバッグオプションだけで保持を保証したと扱わない |
| C ABI の差 | bpfel/bpfeb の比較と wasm32 の静的検査を必須にする。差がある型を初期版では自動変換しない |
| packed と暗黙 padding | codec が位置を扱い、Go のメモリレイアウトと分離する。wire 型の暗黙 padding は初期版で拒否する |
| BTF 型の情報量 | 属性や typedef の起源が消える場合がある。アラインメントなどは C 側で値へ橋渡しする。必要な情報が増えれば AST 方式を再評価する |
| enum とマクロの互換性 | 当初はマクロを維持する。外部の `#if` 利用を調べずに enum へ置換しない。64ビット定数の対応は別途仕様化する |
| 関数の意味のずれ | 関数の自動翻訳はしない。Go の VNI 補助関数を C と同じ入力集合で照合し、C 関数の変更時にも CI が起動するようにする |
| 正本の外部配布 | ヘッダのパスは維持し、外部側で利用するリビジョンと内容ハッシュを記録する。同じリポジトリ内の CI だけでは、外部の古いコピーを検出できない |
| 外部 Cilium の確認範囲 | Cilium v1.20.3 の計測用 `DPP_MODE=6` でコンパイル、ロード、トラフィックを確認済み。環境と再現手順、外部バリアントの保存範囲は11.2節に記録する |
| ツールチェーンの固定 | LLVM 22 を出発点に、fork の BTF 読み出しとの組み合わせを検証する。更新は再生成差分と fixture を同じ変更で確認する |
| Go/TinyGo の差 | 生成物に `unsafe`、`structs.HostLayout`、eBPF ローダーを持ち込まず、対象 TinyGo のバージョンで実行確認する |
| SDK と生成物の版 | guest の公開方法に合わせて、C ヘッダの識別情報と Go 生成物を同じ変更として配布する。破壊的なフィールド変更は公開 API の変更として扱う |

初期公開の範囲は、VXLAN の型と整数定数の生成、明示的な wire codec、Go 版プラグインの移行、再生成による差分検出までとする。
外部観測側での一致を完了とするには、第6段階の確認記録も必要である。
外部環境をまだ確認できない場合は、その検証を未完了と記載し、リポジトリ内での整合性の確認と区別する。

## 10. 今回の検証範囲とデータの保存

段階1〜5では生成器の失敗条件、複数 ABI、Go と TinyGo の Wasm 実行、既存 VXLAN 出力とのバイト一致を確認する。
移行前の Go builder とプラグインの出力を先に採取し、フレーム全体と JSON 応答の意味を移行後と照合する。
性能改善を目的とする変更ではなく、送信ホットパスも変更しないため、トラフィック性能の比較測定は実施しない。
性能測定を追加する場合は対応差の平均と t 分布による95%信頼区間を用いる。
段階1〜5の当時の生ログと移行前 Wasm は保存していない。
リポジトリ内の fixture と検証コードは残るが、当時のログを再確認できるものではない。
段階1〜5については、リポジトリに小さな検証 fixture、検算スクリプト、設計書の結果を残す。
段階6の保存データと未収録のログは11.2節に示す。

関連設計は [混合バリアント](design_mixed_variants.md)、[TCP フローテンプレート](design_tcp_flow_template.md)、[XDP TCP](design_xdp_tcp.md) を参照する。
今回の生成型は guest の値型であり、これらの BPF マップや TCP 状態の ABI を置き換えない。

## 11. 実装の記録

生成器は、manifest の全フィールドに明示的な Go 名を要求する。
構造体のフィールド順と集合、wire/internal の区別、wire の格納順を検査し、非対応型はフィールドパスを付けて拒否する。
名前付き enum を値型として公開する機能と、構造体の入れ子は初期版に含めない。
今回の正本では必要がなく、未確認の意味を補う生成 API を増やさないためである。
整数定数とアラインメントの取得には、C コンパイラが評価した保持用 enum を使用する。

bpf2go の比較では、保持用グローバル変数からの自動型選択と明示的な `-type` が重複するため、`-no-global-types` を併用した。
この検証は `TestBpf2goExtraction` として残し、最終成果物には bpf2go のローダーや ELF を含めない。
BTF での抽出は安定して成立したため、AST 方式への切り替えは不要だった。

Go の既定ポートは `GeneratorRequest.UnmarshalJSON` で生成定数を設定してからデコードする。
既存の defaults 処理が設定した他のフィールドは alias に引き継ぐ。
省略と null は4789、明示的な0は0、任意の指定値はその値を保持することを移行前の実出力と比較した。
VXLAN の8条件の JSON fixture は main の 7b16bbc の Wasm から移行前に採取し、フレーム全体に加えて diff と checksum のメタデータも比較する。

Go/TinyGo の fixture は、新しいパッケージだけを import する独立モジュールとしてビルドし、wazero で実行する。
ホストでは `pkg/guest` の本体と `packetdefs/...` をテストする。
既存の `goshim` は Wasm import を持ち、ホスト向け `go test ./...` はコンパイルできないため、Wasm プラグインのビルドと実行で検証する。

OCR では2人の principal と2人の quality が独立して確認した。
wasm32 の同幅 float と `_Bool` がサイズと符号の検査だけでは通る問題を修正し、整数専用演算と `_Bool` の明示拒否、および拒否 fixture を追加した。
元の指摘を出した両 reviewer が再実行して解消を確認した。

全体 lint の実行で既存の不具合も判明した。
JSON 検査の `jq -e empty` は正しい JSON にも終了コード1を返すため、`jq empty` に修正した。
YAML の字下げと既存の末尾空白も整え、別コミット 7ec17e1 に分けた。

段階1〜5の生ログ、移行前 Wasm、およびコンテナのログは保存していない。
元の作業ディレクトリは削除済みである。
[移行前 JSON fixture](../../pkg/plugin/testdata/vxlan_before/) と [検証コード](../../internal/packetdefs/) はリポジトリに残る。
性能測定は行っておらず、PPS の改善や劣化に関する主張はしない。

### 11.1 検証結果

| 検証 | 結果 |
|---|---|
| bpf2go と BTF の型と定数の抽出 | 成功。Header 8、align 1、VNI offset 4/size 3、InnerKey 16/align 4 |
| bpfel と bpfeb の正規化比較、wasm32 の静的検査 | 成功 |
| packed の多バイト整数と配列の codec | ホストで big/little の両方に成功 |
| 短いバッファ、予約フィールド、後続 payload の維持 | 成功 |
| 非対応型、定数範囲外、Go 名衝突、ABI と型種別の不一致 | 期待どおり生成失敗 |
| マクロ式、include、配列長、manifest の変更、欠落と余剰生成物 | 生成漏れを検出し、再生成後は成功 |
| Go 1.25.5 と TinyGo 0.39.0 のビルドと wazero 実行 | 両方成功 |
| Go 版 VXLAN の移行前後の全バイト比較 | 8条件すべて一致 |
| guest 本体、生成パッケージ、VXLAN builder の sudo race | 成功 |
| 固定コンテナでの再生成比較と専用 race | 成功 |
| 全ファイル lint と生成パッケージ、builder の lint | 成功 |
| `make build` と `make test-runnable` | 成功 |
| ルート全体の `make test` | 全パッケージ sudo race 成功（skip なし） |
| `make examples` の12シナリオ | 12/12 成功、失敗と skip は0 |
| OCR レビュー | 修正必須の指摘を解消、APPROVE |
| 実際の Cilium Datapath Plugin での段階6 | 2026-10-21 に冒頭の範囲で成功。Go/C 版の内側 tuple と VNI、実送信数に対するカウンタが一致。アタッチとロード状態は作業時の観測として記録（11.2節） |

### 11.2 段階6の Cilium Datapath Plugin での確認

2026-10-21 に、共有ヘッダを使う外部観測側でコンパイル、ロード、生成トラフィックの照合を行った。
この確認は定義の共有と観測結果の一致を対象とし、性能比較の結果ではない。

#### 環境と入力の固定

| 項目 | 条件 |
|---|---|
| ホスト | Ubuntu 26.04、kernel 7.0.0-38-generic、x86_64 |
| クラスタ | kind v0.33.0、Kubernetes v1.37.0、control plane 1台と worker 2台 |
| Cilium | v1.20.3、veth、TCX、native routing、kube-proxy replacement |
| xdperf と共有ヘッダ | main `58573baf6c6d63869a3c7421ff21811717c2dab5`（#127 の変更後）の `plugins/vxlan.c/vxlan_shared.h` |
| 観測側 | Cilium v1.20.3 の `examples/datapath-plugin` に計測用バリアント `DPP_MODE=6` を適用 |
| BPF コンパイル | clang-22、`-O2 -g --target=bpf -mcpu=v3` |

共有ヘッダと Go 生成物の SHA-256 は次のとおりである。
後者は `pkg/guest/packetdefs/vxlan/types_gen.go` の内容ハッシュである。

```text
5fa16267b36e75a380a8abfc58b8367a8208f7465ce9cb8114652cda577e459a  plugins/vxlan.c/vxlan_shared.h
977e83cfa2243fd7741220c5fc52c517a9c58a48aa2c3812464c786a8a128656  pkg/guest/packetdefs/vxlan/types_gen.go
```

バリアントは共有ヘッダを include し、`vx_load16` / `vx_load32` と `vxlan_vni` で内側 IPv4 アドレス、UDP ポート、VNI を数値化する。
キーは `struct vx_inner_key`、値はカウンタとし、`dpp_vx_flows` を最大65,536エントリの `LRU_HASH` として定義した。
内側のプロトコルは UDP に固定した確認であり、キーにプロトコル番号のフィールドはない。
計数処理は skb フックだけに置き、他のフックは空にした。
当時の4つの `.o` から出し直した [objects.txt](benchmarks/stage6-cilium/objects.txt) に、各オブジェクトの SHA-256 と `__bpf_trap`、`trace_printk` がともに0件であることを収録した。
`CiliumDatapathPlugin` によるロードで182フックがアタッチされ、verifier エラーなし（Datapath Plugin の DaemonSet が Running、ロード後に再起動なし）だったことは作業時の観測である。
その生ログはホストの IP を含むため収録しない。

#### レイアウトとキーの格納順

Cilium 側 `skb_bpfel.o` の BTF 抜粋を [objects.txt](benchmarks/stage6-cilium/objects.txt) に収録した。
次の配置を示し、[生成済みレイアウト](../../pkg/guest/packetdefs/vxlan/layout_gen.json) と一致した。

| 型またはフィールド | サイズまたはオフセット（バイト） |
|---|---|
| `vx_inner_key` | size 16 |
| `saddr` | offset 0 |
| `daddr` | offset 4 |
| `sport` | offset 8 |
| `dport` | offset 10 |
| `vni` | offset 12 |

マップから得た生のキーの一例は `0100a8c00200a8c00004c41367000000` である。
これは `192.168.0.1:1024 -> 192.168.0.2:5060`、VNI 103 に対応する。
各フィールドは読み出し関数が返した数値を BPF を実行するホストのバイト順で格納するため、検証した x86_64 ではリトルエンディアンになる。
たとえば送信元 `192.168.0.1` は数値 `0xc0a80001` であり、キー内のバイト列は `01 00 a8 c0` だった。

この観測側のキーは BPF を実行するホストのバイト順であり、ネットワーク順ではない。
固定した共有ヘッダには `network byte order` というコメントが残るが、この代入処理と生バイト列には合致しない。
Go の `InnerKey` をこの外部マップと交換する場合も、生成済みオフセットに従って BPF を実行するホストのバイト順で読み書きする必要がある。
今回の変更では `InnerKey` の codec や新しい API は追加せず、格納順の結論だけを記録する。
この結論は数値化して代入する当該観測側に対するものであり、パケット上のネットワーク順を変更するものではない。

#### 生成トラフィックの照合

client Pod（kind ノード `xdp-worker` 上）の `eth0` に generic XDP を使い、xdperf `58573ba` から20,000 pps、parallelism 1を指定して送信した。
宛先は responder Pod（kind ノード `xdp-worker2` 上）の Pod IP、外側 UDP 送信元ポートは49152固定とした。
観測点は client の lxc の `from_container` に付いた `before` フックの `dpp_vx_flows` である。
内側は `192.168.0.1 -> 192.168.0.2`、UDP 宛先ポート5060とした。

| 試行 | 送信条件 | 実送信数 | マップでの観測 |
|---|---|---|---|
| A | Go 版 `vxlan.go`、VNI 100〜115、内側送信元ポート1024、128バイト | 16,000 | 16キー × 1,000、計16,000 |
| B | Go 版、VNI 200固定、`vary_inner_port` で内側送信元ポート65280〜65535 | 24,000 | 256キー、各93または94、計24,000。ポートは連続 |
| C | C 版 `vxlan.c`、VNI 300、`inner_sport_base=65280`、`inner_flows=256` | 24,000 | Go 版の試行 B と同じ分布、計24,000 |

送信元 IP、宛先 IP、宛先ポート、VNI はすべて期待値と一致した。
試行 B と C は `--count 25600` を指定したが、`--pps` のバッチ単位の切り捨てにより実送信数は24,000だった。
カウンタは実送信数に対して照合し、一致した。
当時は1バッチ2,000パケットで、12バッチ × 2,000 = 24,000となった。
この切り捨ての修正は [PR #133](https://github.com/takehaya/xdperf/pull/133) で扱い、本確認には含めない。

[runA.json](benchmarks/stage6-cilium/runA.json) は試行 A 後、[runBC.json](benchmarks/stage6-cilium/runBC.json) は試行 B と C の後のダンプである。
後者には試行 A のキーも残るため、VNI 100〜115、200、300に分けて集計する。
取得スクリプトとデータの読み方は [保存データの README](benchmarks/stage6-cilium/README.md) を参照する。

#### 再現手順と保存範囲

各試行で使った CLI フラグと `--cfg` は次のとおりである。
`<client-pod-ip>`、`<responder-pod-ip>`、`<client-mac>` は各 Pod の値に置き換える。
`<gateway-mac>` は client Pod の既定ゲートウェイ（Cilium の lxc）の MAC である。
WASM ファイルは各 Pod のプラグイン検索パスに配置する。

試行 A:

```sh
xdperf run --device eth0 --xdp-mode generic --pps 20k --parallelism 1 \
  -L go -p vxlan.go --count 16000 \
  --cfg '{"src_ip":"<client-pod-ip>","dst_ip":"<responder-pod-ip>","dst_mac":"<gateway-mac>","is_arp_resolve":false,"src_port":49152,"vni_start":100,"vni_end":115,"inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2","inner_src_port":1024,"inner_dst_port":5060,"imix_sizes":[128],"imix_weights":[1]}'
```

試行 B（A と同じ設定を基に、VNI、内側送信元ポート、ポート走査を変更）:

```sh
xdperf run --device eth0 --xdp-mode generic --pps 20k --parallelism 1 \
  -L go -p vxlan.go --count 25600 \
  --cfg '{"src_ip":"<client-pod-ip>","dst_ip":"<responder-pod-ip>","dst_mac":"<gateway-mac>","is_arp_resolve":false,"src_port":49152,"vni_start":200,"vni_end":200,"inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2","inner_src_port":65280,"inner_dst_port":5060,"imix_sizes":[128],"imix_weights":[1],"vary_inner_port":true}'
```

試行 C（外側 `src_port` は既定の49152、`payload` は既定の18バイト）:

```sh
xdperf run --device eth0 --xdp-mode generic --pps 20k --parallelism 1 \
  -L c -p vxlan.c --count 25600 \
  --cfg '{"src_mac":"<client-mac>","dst_mac":"<gateway-mac>","src_ip":"<client-pod-ip>","dst_ip":"<responder-pod-ip>","vni":300,"inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2","inner_dport":5060,"inner_sport_base":65280,"inner_flows":256}'
```

計測用バリアントはリポジトリ外にあり、本リポジトリには取り込まない。
そのソースと Cilium v1.20.3 の作業環境を別途用意する必要があり、本リポジトリの保存データだけで Plugin の再ビルドやロードを再現できるわけではない。
手順の要点は次のとおりである。

1. Cilium v1.20.3 の `examples/datapath-plugin` に外部の `variants.patch` を適用し、`variant.h` を BPF ソースのディレクトリへ置く。
   上記ハッシュの `vxlan_shared.h` を同じディレクトリから include できるようにし、`DPP_MODE=6` でビルドする。
   skb 以外も含めた全4オブジェクトで `__bpf_trap` と `trace_printk` が残らないこと、および BTF の配置を確認する。
2. `.o` を埋め込む Go バイナリを再ビルドして Plugin のイメージを作り、kind にロードする。
   `CiliumDatapathPlugin` で有効化し、フックのアタッチと verifier エラーの有無を確認する。
3. 上表の条件で Go/C 版トラフィックを送り、client の lxc に対応するマップを読み出す。
   [s6dump.py](benchmarks/stage6-cilium/s6dump.py) は kind ノードのネットワーク名前空間で `from_container` のプログラム ID を求め、tracing link の接続先と `before` の名前からマップを特定する。
   `bpftool -j` の生キーを BTF のオフセットに合わせて `struct.unpack("<IIHHI", ...)` で解釈し、VNI と内側送信元ポート順に並べる。
   このスクリプトのリトルエンディアン指定は当時の x86_64 環境用である。
4. 確認後に Plugin を外し、ホスト側の状態を比較する。
   ホストの上流 NIC の XDP/tc、cgroup root、経路、nft の行数、外部疎通が、作業前、ロード後、最後の3時点で差分なしだったことは作業時の観測である。
   その生ログはホストの IP を含むため収録しない。

保存するのは `s6dump.py`、`runA.json`、`runBC.json`、`objects.txt` と説明用 README である。
ホストの IP を含む `host_*.txt`、バイナリ、外部バリアントはコミットしない。
