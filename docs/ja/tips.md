# tips
## なぜかpacketが飛んでいかない
### Dummy XDP　ProgをAttachしていない
何も気にしないで実行するとこんな感じで失敗してしまってるのがわかる。以下`trace-cmd`の様子です。
```shell
$ sudo trace-cmd stream -e xdp
Hit Ctrl^C to stop recording
^C           <...>-386962 [000]1134275821948249: bpf_trace_printk:     tx packet len=1066, iface=3
           <...>-386962 [000]1134275821952317: xdp_redirect_err:     prog_id=401 action=REDIRECT ifindex=3 to_ifindex=3 err=-95 map_id=2147483647 map_index=0
           <...>-386962 [000]1134275821961487: mem_disconnect:       mem_id=27 mem_type=PAGE_POOL allocator=0xffff8cfb0164b000
```
これはXDP TX Queue が割り当てられていないから起きるもので、多くのNICドライバ（virtio_net, ixgbe, ena など）は、メモリ節約のため、XDPプログラムが実際にアタッチされるまで、XDP用の送信リソース（TX Queue/Ring）を確保しません。
`BPF_PROG_RUN` はbpf(2)経由でプログラムを単発実行するだけなので、これだけではドライバはXDPパケットを送信する準備をしません。そのため、送信しようとするとエラーになります。

そこで`XDP_PASS`だけをするダミーアプリを仕掛けておくとこの問題は解決します。

以下のような結果になっていい感じになります。
```shell
$ sudo trace-cmd stream -e xdp
Hit Ctrl^C to stop recording
^C           <...>-389361 [000]1135399003823858: bpf_trace_printk:     tx packet len=1066, iface=3
           <...>-389361 [000]1135399003826791: xdp_redirect:         prog_id=409 action=REDIRECT ifindex=3 to_ifindex=3 err=0 map_id=2147483647 map_index=0
           <...>-389361 [000]1135399003835812: xdp_devmap_xmit:      ndo_xdp_xmit from_ifindex=3 to_ifindex=3 action=REDIRECT sent=1 drops=0 err=0
           <...>-386613 [000]1135400018427418: mem_disconnect:       mem_id=29 mem_type=PAGE_POOL allocator=0xffff8cfb0164b000
```

実際動いてるかどうかは統計を見るのも良いでしょう.
```shell
$ sudo ethtool -S ens4
NIC statistics:
     rx_queue_0_packets: 2
     rx_queue_0_bytes: 158
     rx_queue_0_drops: 0
     rx_queue_0_xdp_packets: 0
     rx_queue_0_xdp_tx: 0
     rx_queue_0_xdp_redirects: 0
     rx_queue_0_xdp_drops: 0
     rx_queue_0_kicks: 1
```

## パフォーマンスチューニング
そもそも肝心要のパケットの負荷を掛けれる性能が微妙だと困るという話があるので、それを検証してみる。
output性能が十分出るかを見たい。環境は virtio-net ドライバ上のVMである。

### ベースラインを見てみる
```shell
$ sudo ./out/bin/xdperf run --device=ens4 --count 100k --parallelism 15 --infinite --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1500}'
// 略
6,460,859 xmit/s, 19,273.75 Mbps
4,769,462 xmit/s, 14,223.81 Mbps
5,761,387 xmit/s, 17,177.78 Mbps
6,106,471 xmit/s, 18,151.25 Mbps
6,096,178 xmit/s, 18,196.34 Mbps
```

おおよそ、6Mpps, 20GbE程度がベースラインである。

### Batchingを導入してみよう
```shell
$ sudo ./out/bin/xdperf run --device=ens4 --count 100k --parallelism 15 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1500}'
// 略
12,291,417 xmit/s, 36,921.00 Mbps
11,160,965 xmit/s, 33,526.75 Mbps
12,733,755 xmit/s, 38,266.04 Mbps
12,455,024 xmit/s, 37,396.23 Mbps
```
XDP_LIVE_FRAMEの batch modeを有効化して 64ずつBatchで実行させた。これでシステムコールのオーバーヘッドが下がるはず。
結果として12Mppsぐらいまで出る様になった。（約2倍）

https://github.com/cilium/ebpf/pull/1914
余談だが、cilium/ebpfにはなぜかBatchパラメーターが抜けてたためここでPRを出している。

### memcpy 最適化をしてみよう
おそらくメモリコピーをXDPでやってるところがあれなのでそれをバルクにしてみる。
`bpf_xdp_store_bytes`を使うといい感じなはず。
```shell
ubuntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 10k --parallelism 19 --infinite --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}' --batch-size 64
// 略
43,207,038 xmit/s, 113,437.72 Mbps
40,140,974 xmit/s, 105,328.41 Mbps
40,542,491 xmit/s, 106,130.42 Mbps
42,450,419 xmit/s, 111,791.40 Mbps
43,017,559 xmit/s, 112,440.86 Mbps
41,467,995 xmit/s, 107,784.49 Mbps
```
43Mppsぐらいまで出る様になった！

### lookup最適化をしよう
xdpcapというのを使ってるのでOutput時にオーバーヘッドがあるはず。
ということでBypassしてみよう

```shell
$ sudo ./out/bin/xdperf run --device=ens4 --count 10k --parallelism 15 --infinite --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}' --batch-size 64
//中略
49,158,284 xmit/s, 122,799.44 Mbps
47,584,312 xmit/s, 118,875.64 Mbps
48,632,159 xmit/s, 121,524.72 Mbps
47,035,791 xmit/s, 117,617.69 Mbps
50,044,908 xmit/s, 124,941.08 Mbps
45,897,239 xmit/s, 114,771.17 Mbps
44,258,582 xmit/s, 110,253.30 Mbps
49,253,583 xmit/s, 123,073.99 Mbps
49,308,601 xmit/s, 122,573.57 Mbps
49,486,269 xmit/s, 123,342.60 Mbps
48,850,954 xmit/s, 122,464.80 Mbps
51,566,601 xmit/s, 128,884.97 Mbps
50,532,993 xmit/s, 126,293.31 Mbps
50,901,081 xmit/s, 127,582.12 Mbps
49,099,353 xmit/s, 123,009.10 Mbps
43,683,748 xmit/s, 108,397.95 Mbps
41,833,397 xmit/s, 103,661.99 Mbps
45,113,523 xmit/s, 112,254.67 Mbps
```
だいたい同じぐらいだけど、ピーク性能で50Mpps程度達成してる！！！

### 性能向上まとめ
| 最適化段階 | 性能 | 改善率 |
|-----------|------|--------|
| **最適化前** | 5〜6.5 Mpps (14〜19 Gbps) | ベースライン |
| **batch-size=64 追加** | 11〜12.7 Mpps (33〜38 Gbps) | +100% (2倍) |
| **bpf_xdp_store_bytes 適用** | 40〜43 Mpps (105〜113 Gbps) | +560% |
| **xdpcap バイパス** | **45〜51 Mpps (115〜129 Gbps)** | **+700%** |

ちなみに1coreあたりの性能だと3Mppsぐらいだった。

```shell
buntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 1k --parallelism 1 --infinite --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1500}' --batch-size 64
// 略
3,556,608 xmit/s, 10,249.85 Mbps
3,586,404 xmit/s, 10,335.56 Mbps
3,342,812 xmit/s, 9,633.70 Mbps
3,334,248 xmit/s, 9,608.88 Mbps
3,283,589 xmit/s, 9,463.06 Mbps
3,374,481 xmit/s, 9,724.83 Mbps
3,373,207 xmit/s, 9,721.27 Mbps
3,411,755 xmit/s, 9,832.30 Mbps
3,358,134 xmit/s, 9,677.79 Mbps
3,372,807 xmit/s, 9,720.08 Mbps
3,416,713 xmit/s, 9,846.65 Mbps
3,358,174 xmit/s, 9,677.87 Mbps
```
なお、開発者曰く 1core 8Mppsぐらい行けるらしいので、もっと最適化余地があったりしそうだなというのが感想にある。
cf. https://blog.tohojo.dk/2023/05/the-xdp-traffic-generator.html
cf. https://drive.google.com/file/d/1e7JWfHt2GKucZ8YZaQhXN3ehHcoNxOT6/view

### 他にやってみると効果があること
- mapに入れる値を小さくする
```shell
ubuntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 15 --parallelism 15 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}'
// 略
50,576,340 xmit/s, 82,065.71 Mbps
55,577,100 xmit/s, 81,185.65 Mbps
52,759,999 xmit/s, 90,257.40 Mbps
53,575,053 xmit/s, 88,963.45 Mbps
55,315,762 xmit/s, 81,972.27 Mbps
55,143,170 xmit/s, 80,380.75 Mbps
51,576,616 xmit/s, 74,317.45 Mbps
52,080,944 xmit/s, 79,093.37 Mbps
53,885,907 xmit/s, 89,294.70 Mbps
59,130,213 xmit/s, 94,118.83 Mbps
57,850,993 xmit/s, 96,557.89 Mbps
54,618,676 xmit/s, 77,691.19 Mbps
56,565,368 xmit/s, 84,988.42 Mbps
59,225,493 xmit/s, 100,117.31 Mbps
58,396,611 xmit/s, 99,576.44 Mbps
57,447,319 xmit/s, 95,174.94 Mbps
```
59Mppsぐらい出ててすごい。

### もうちょい目指すなら・・・？
```shell
=== NIC IRQs ===
ubuntu@takehaya-main:~/private/xdperf$ ethtool -g ens4
Ring parameters for ens4:
Pre-set maximums:
RX:                     256
RX Mini:                n/a
RX Jumbo:               n/a
TX:                     256
TX push buff len:       n/a
Current hardware settings:
RX:                     256
RX Mini:                n/a
RX Jumbo:               n/a
TX:                     256
RX Buf Len:             n/a
CQE Size:               n/a
TX Push:                off
RX Push:                off
TX push buff len:       n/a
TCP data split:         n/a
```
この辺のNICの環境とかが良ければワンチャンありそう。

また、batch-sizeを変化して試してみるのはアリなのかもしれない。

### 余談
この実装はeBPF Mapに任意のパケットを書き込んでおいてそれを上書きすることで高速にパケットを投げつけている。
そこであえてその変更をコメントアウトしてみたらどうなるか確かめてみる。
#### 1core
おおよそ5Mppsほどが出てる。
```shell
ubuntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 1 --parallelism 1 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}'
//　略
5,242,880 xmit/s, 60,000.00 Mbps
5,154,193 xmit/s, 58,985.06 Mbps
5,133,179 xmit/s, 58,744.57 Mbps
5,169,797 xmit/s, 59,163.63 Mbps
5,200,144 xmit/s, 59,510.93 Mbps
5,159,632 xmit/s, 59,047.30 Mbps
5,109,120 xmit/s, 58,469.24 Mbps
5,062,048 xmit/s, 57,930.54 Mbps
5,164,911 xmit/s, 59,107.72 Mbps
5,178,880 xmit/s, 59,267.58 Mbps
```

#### Multicore
おおよそピーク性能で69Mppsほどでてる
```shell
ubuntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 15 --parallelism 15 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}'
// 略
67,429,179 xmit/s, 771,666.21 Mbps
56,420,664 xmit/s, 645,682.77 Mbps
46,106,056 xmit/s, 527,641.94 Mbps
62,397,043 xmit/s, 714,077.49 Mbps
65,086,239 xmit/s, 744,852.89 Mbps
60,040,537 xmit/s, 687,109.42 Mbps
55,475,055 xmit/s, 634,861.62 Mbps
68,667,683 xmit/s, 785,839.27 Mbps
67,937,393 xmit/s, 777,481.76 Mbps
66,590,419 xmit/s, 762,066.87 Mbps
69,617,474 xmit/s, 796,708.76 Mbps
```

この事から1coreで2Mpps, Multiで最大10Mppsほどがこの書き換えでオーバーヘッドになってることがわかった。
