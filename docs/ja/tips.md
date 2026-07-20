# tips
## なぜかpacketが飛んでいかない
### Dummy XDP ProgをAttachしていない
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

## パフォーマンスチューニング(virtio-net編)
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

> 補記: その後、xdpcap のフック (`RETURN_ACTION` / `xdpcap_hook`) を XDP プログラムから完全に撤去し、キャプチャは非侵襲な [xdp-ninja](https://github.com/takehaya/xdp-ninja) に移行した。ホットパスから分岐が消えたため、上表の「バイパス」時と同等の性能が常時の既定となっている。

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
ubuntu@takehaya-main:~/private/xdperf$ sudo ./out/bin/xdperf run --device=ens4 --count 15 --parallelism 15 --infinite --batch-size 256 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200}'
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

## パフォーマンスチューニング(intel ice編)　20260322
要はベアメタルサーバーでのチューニングという話。
とりあえずこの辺をやっておくと良い。

```shell
# とりあえずiommu=pt (passthrough) にすると、DMAアドレス変換をバイパスしてロック競合がなくなる。
# DMA アドレス変換を バイパス し、デバイスが物理アドレスを直接使うので、IOTLB フラッシュ不要、結果として spinlock 競合が消える。
GRUB_CMDLINE_LINUX_DEFAULT="mitigations=off iommu=pt"
sudo sed -i 's/mitigations=off/mitigations=off iommu=pt/' /etc/default/grub
sudo update-grub
sudo reboot

# txのリングを描くと、むしろキャッシュに乗らなくなるので下げた方がいい
sudo ethtool -G enp138s0f0np0 tx 256
```

以下に実際の結果のビフォーアフターを載せておく。なお、パケットのランダマイズとかは全然聞いてないという実装でマイクロベンチの参考として利用するのが望ましい。

### 1core(before)
```shell
$ sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" --count 1 --parallelism 1 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}'
2026-03-21T22:52:26Z    INFO    xdperf wasm plugin loader initialized
2026-03-21T22:52:26Z    INFO    calculated map sizes    {"tx_override_map_size": 2, "diff_map_size": 2}
2026-03-21T22:52:26Z    INFO    xdperf xdp code loader initialized
2026-03-21T22:52:26Z    INFO    start client mode
2026-03-21T22:52:26Z    INFO    testing simple plugin communication
[PLUGIN] [1] plugin initialized!: msg ->{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}
[PLUGIN] [1] plugin version: dev, commit: none, date: unknown
2026-03-21T22:52:26Z    INFO    plugin initialized successfully
2026-03-21T22:52:26Z    INFO    calling plugin  {"merged_config": {"count":1,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0","dst_ip":"192.168.1.2","dst_port":10001,"is_arp_resolve":false,"payload_size":1200,"src_ip":"192.168.1.1"}}
[PLUGIN] [1] plugin_process called with input: {"src_ip":"192.168.1.1","dst_ip":"192.168.1.2","dst_mac":"ff:ff:ff:ff:ff:ff","is_arp_resolve":false,"src_port":1234,"dst_port":10001,"payload_size":1200,"count":1,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0"}
[METRIC] gen resp count 1.000000 time=2026-03-21T22:52:26.745770481Z
[PLUGIN] [1] response sent
2026-03-21T22:52:26Z    INFO    after GenerateTemplate success
2026-03-21T22:52:26Z    INFO    received response       {"pattern": "sequential", "raw_packet_template_count": 0, "variable_packet_template_count": 1}
2026-03-21T22:52:26Z    INFO    plugin call successful
2026-03-21T22:52:26Z    INFO    packet entries generated        {"template_type": "variable", "num_bases": 1, "num_entries": 1, "total_checksums": 2}
2026-03-21T22:52:26Z    INFO    packet distribution calculated  {"total_entries": 1, "num_bases": 1, "parallelism": 1, "num_cpus": 64, "counts_per_cpu": [1]}
2026-03-21T22:52:26Z    INFO    base packet maps initialized    {"num_bases": 1}
2026-03-21T22:52:26Z    INFO    diff map populated      {"num_entries": 1, "num_cpus": 64, "max_count_per_cpu": 1}
2026-03-21T22:52:26Z    INFO    checksum meta maps initialized  {"num_bases": 1, "total_checksums": 2}
2026-03-21T22:52:26Z    INFO    BPF maps initialized
2026-03-21T22:52:26Z    INFO    TX packet processing started (infinite) {"parallelism": 1, "packet_pool_size": 1, "target_pps": 0, "repeat_per_batch": 1048576, "batch_size": 64, "total_batches_per_cpu": 0, "batch_interval": "0s", "infinite_mode": true}
1,694,193 xmit/s, 827.24 Mbps
1,688,832 xmit/s, 824.62 Mbps
1,714,800 xmit/s, 837.30 Mbps
1,682,897 xmit/s, 821.73 Mbps
1,704,149 xmit/s, 832.10 Mbps
1,728,537 xmit/s, 844.01 Mbps
1,688,219 xmit/s, 824.33 Mbps
1,719,123 xmit/s, 839.42 Mbps
```

### 1core(after)
```shell
$ sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" --count 1 --parallelism 1 --infinite --batch-size 256 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}'
2026-03-21T23:51:10Z    INFO    xdperf wasm plugin loader initialized
2026-03-21T23:51:10Z    INFO    calculated map sizes    {"tx_override_map_size": 2, "diff_map_size": 2}
2026-03-21T23:51:10Z    INFO    xdperf xdp code loader initialized
2026-03-21T23:51:10Z    INFO    start client mode
2026-03-21T23:51:10Z    INFO    testing simple plugin communication
[PLUGIN] [1] plugin initialized!: msg ->{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}
[PLUGIN] [1] plugin version: dev, commit: none, date: unknown
2026-03-21T23:51:10Z    INFO    plugin initialized successfully
2026-03-21T23:51:10Z    INFO    calling plugin  {"merged_config": {"count":1,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0","dst_ip":"192.168.1.2","dst_port":10001,"is_arp_resolve":false,"payload_size":1200,"src_ip":"192.168.1.1"}}
[PLUGIN] [1] plugin_process called with input: {"src_ip":"192.168.1.1","dst_ip":"192.168.1.2","dst_mac":"ff:ff:ff:ff:ff:ff","is_arp_resolve":false,"src_port":1234,"dst_port":10001,"payload_size":1200,"count":1,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0"}
[METRIC] gen resp count 1.000000 time=2026-03-21T23:51:10.677664812Z
[PLUGIN] [1] response sent
2026-03-21T23:51:10Z    INFO    after GenerateTemplate success
2026-03-21T23:51:10Z    INFO    received response       {"pattern": "sequential", "raw_packet_template_count": 0, "variable_packet_template_count": 1}
2026-03-21T23:51:10Z    INFO    plugin call successful
2026-03-21T23:51:10Z    INFO    packet entries generated        {"template_type": "variable", "num_bases": 1, "num_entries": 1, "total_checksums": 2}
2026-03-21T23:51:10Z    INFO    packet distribution calculated  {"total_entries": 1, "num_bases": 1, "parallelism": 1, "num_cpus": 64, "counts_per_cpu": [1]}
2026-03-21T23:51:10Z    INFO    base packet maps initialized    {"num_bases": 1}
2026-03-21T23:51:10Z    INFO    diff map populated      {"num_entries": 1, "num_cpus": 64, "max_count_per_cpu": 1}
2026-03-21T23:51:10Z    INFO    checksum meta maps initialized  {"num_bases": 1, "total_checksums": 2}
2026-03-21T23:51:10Z    INFO    BPF maps initialized
2026-03-21T23:51:10Z    INFO    TX packet processing started (infinite) {"parallelism": 1, "packet_pool_size": 1, "target_pps": 0, "repeat_per_batch": 1048576, "batch_size": 256, "total_batches_per_cpu": 0, "batch_interval": "0s", "infinite_mode": true}
2,335,807 xmit/s, 22,133.43 Mbps
2,382,658 xmit/s, 22,577.37 Mbps
2,386,800 xmit/s, 22,616.62 Mbps
2,344,430 xmit/s, 22,215.13 Mbps
2,384,529 xmit/s, 22,595.10 Mbps
2,385,075 xmit/s, 22,600.27 Mbps
2,336,158 xmit/s, 22,136.75 Mbps
```

### 50core(after)
```shell
$ sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" --count 50 --parallelism 50 --infinite --batch-size 64 --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64, "is_arp_resolve":false}'
2026-03-21T23:15:37Z    INFO    xdperf wasm plugin loader initialized
2026-03-21T23:15:37Z    INFO    calculated map sizes    {"tx_override_map_size": 2, "diff_map_size": 2}
2026-03-21T23:15:38Z    INFO    xdperf xdp code loader initialized
2026-03-21T23:15:38Z    INFO    start client mode
2026-03-21T23:15:38Z    INFO    testing simple plugin communication
[PLUGIN] [1] plugin initialized!: msg ->{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64, "is_arp_resolve":false}
[PLUGIN] [1] plugin version: dev, commit: none, date: unknown
2026-03-21T23:15:38Z    INFO    plugin initialized successfully
2026-03-21T23:15:38Z    INFO    calling plugin  {"merged_config": {"count":50,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0","dst_ip":"192.168.1.2","dst_port":10001,"is_arp_resolve":false,"payload_size":64,"src_ip":"192.168.1.1"}}
[PLUGIN] [1] plugin_process called with input: {"src_ip":"192.168.1.1","dst_ip":"192.168.1.2","dst_mac":"ff:ff:ff:ff:ff:ff","is_arp_resolve":false,"src_port":1234,"dst_port":10001,"payload_size":64,"count":50,"device_mac_addr":"QKa3laLQ","device_name":"enp138s0f0np0"}
[METRIC] gen resp count 1.000000 time=2026-03-21T23:15:38.104877516Z
[PLUGIN] [1] response sent
2026-03-21T23:15:38Z    INFO    after GenerateTemplate success
2026-03-21T23:15:38Z    INFO    received response       {"pattern": "sequential", "raw_packet_template_count": 0, "variable_packet_template_count": 1}
2026-03-21T23:15:38Z    INFO    plugin call successful
2026-03-21T23:15:38Z    INFO    packet entries generated        {"template_type": "variable", "num_bases": 1, "num_entries": 50, "total_checksums": 2}
2026-03-21T23:15:38Z    INFO    packet distribution calculated  {"total_entries": 50, "num_bases": 1, "parallelism": 50, "num_cpus": 64, "counts_per_cpu": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]}
2026-03-21T23:15:38Z    INFO    base packet maps initialized    {"num_bases": 1}
2026-03-21T23:15:38Z    INFO    diff map populated      {"num_entries": 50, "num_cpus": 64, "max_count_per_cpu": 1}
2026-03-21T23:15:38Z    INFO    checksum meta maps initialized  {"num_bases": 1, "total_checksums": 2}
2026-03-21T23:15:38Z    INFO    BPF maps initialized
2026-03-21T23:15:38Z    INFO    TX packet processing started (infinite) {"parallelism": 50, "packet_pool_size": 50, "target_pps": 0, "repeat_per_batch": 1048576, "batch_size": 64, "total_batches_per_cpu": 0, "batch_interval": "0s", "infinite_mode": true}
110,505,244 xmit/s, 89,367.34 Mbps
113,027,996 xmit/s, 91,407.53 Mbps
108,708,027 xmit/s, 87,913.90 Mbps
107,752,480 xmit/s, 87,141.13 Mbps
107,804,080 xmit/s, 87,182.86 Mbps
107,955,753 xmit/s, 87,305.53 Mbps
107,731,458 xmit/s, 87,124.13 Mbps
107,816,944 xmit/s, 87,193.27 Mbps
107,567,108 xmit/s, 86,991.22 Mbps
107,738,984 xmit/s, 87,130.22 Mbps
107,794,842 xmit/s, 87,175.39 Mbps
107,690,096 xmit/s, 87,090.68 Mbps
107,477,386 xmit/s, 86,918.66 Mbps
```

### perf撮り方
ちなみにこうやるとカーネルの性能情報が取れそう
```shell
# 実行中にこれを起動する
sudo perf record -g -a -- sleep 5

# この辺を使ってみてみると色々わかる
sudo perf report --sort=symbol --no-children | head -30
```

## パフォーマンスチューニング(intel ice編)　20260413
さらに性能を上げたいね？ということでベースパケットに対する冗長なコピーを省略することを試みる

## NUMA を意識した CPU 選択 (--cpu-mode)
マルチソケット機(2ソケット以上)だと、NIC が刺さってる NUMA ノードと、worker スレッドを回す CPU のノードがズレると地味に遅い。
パケットバッファや BPF マップへのアクセスがクロスノードのメモリアクセスになるからね。
なので worker を NIC ローカルなノードの CPU に寄せてやると効く。`--cpu-mode` でこれを制御する(デフォルト `auto`)。

シングルソケット機や VM だとそもそもノードが1個なので、何を指定しても先頭 N コアに固定されるだけ。気にしなくていい。

### まず自分の構成を見る
```shell
# NIC がどの NUMA ノードに繋がってるか (-1 なら affinity なし or 単一ノード)
cat /sys/class/net/enp138s0f0np0/device/numa_node

# 各ノードにどの CPU がいるか
lscpu | grep NUMA
# もしくは
numactl --hardware
```
例えば `numa_node` が `1` で、ノード1 が CPU 24-47 みたいに出てくる構成なら、その範囲に worker を寄せたい。

### モード早見
| モード | 挙動 |
|--------|------|
| `auto` (デフォルト) | NIC ローカルノードを優先。`--parallelism` がローカルのコア数を超えたら他ノードに溢れる |
| `local` | NIC ローカルノードのみ。`--parallelism` がそのノードのコア数を超えたらエラーで落ちる(fail fast) |
| `balanced` | 全ノードにラウンドロビンで均等配分 |
| `node:<N>` | 指定したノード N の CPU に固定 |
| `0,2,4,6` 等 | CPU 番号を直接指定。**この場合 `--parallelism` は無視され、リストの個数がスレッド数になる** |

### 使い分け
- 基本は `auto` で放っておけば NIC ローカルに寄る。普段はこれでいい。
- きっちり縛って「ローカルから溢れたら気付きたい」なら `local`(溢れるとエラーになる)。
- ハイパースレッドの片方だけ使いたい等、手で固定したいなら CPU リスト直指定(例 `--cpu-mode 8,10,12,14`)。
- 散らした場合との比較実験をしたいなら `balanced`。

```shell
# NIC ローカルノードに 8 worker を寄せる(溢れたらエラー)
sudo ./out/bin/xdperf run --plugin=simpleudp.go --device=enp138s0f0np0 --plugin-path="./out/bin" \
  --count 10k --parallelism 8 --infinite --batch-size 64 --cpu-mode local \
  --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 1200, "is_arp_resolve":false}'
```

### 効いてるかの確認
起動時のログに `CPU selection` 行が出るので、`selected_cpus` が狙ったノードの CPU 番号になってるか見る。
```
INFO  CPU selection  {"mode": "local", "selected_cpus": [24,25,26,27,28,29,30,31], "parallelism": 8}
```
あとは `auto`/`local` 指定で `numa_node=-1`(affinity なし)のデバイスを掴むと、ローカルノードに寄せられず先頭 N コアにフォールバックする点に注意。物理 NIC ならまず付いてるはずだけど、veth とかだと付いてないことがある。


## XDP attach モードの選択 (--xdp-mode) 20260720

XDP プログラムのアタッチモードを `--xdp-mode` で制御できる(デフォルト `auto`)。

| モード | 挙動 |
|--------|------|
| `auto` (デフォルト) | フラグなしでアタッチ(ドライバ対応なら native)。失敗したら warn ログを出して generic (SKB) mode にフォールバック |
| `native` | driver (native) mode を強制。非対応ならエラー(fail fast) |
| `generic` | generic (SKB) mode を強制 |

ContainerLab の veth みたいに native アタッチが通らない環境でも、`auto` のままなら generic に落ちて動く。
逆に性能測定で「知らないうちに generic で走ってた」を避けたいなら `native` を指定しておくと失敗で気付ける。
generic mode は skb 経由のスローパスなので性能は大きく落ちる。フォールバック発動時は warn ログ
(`native XDP attach failed; fell back to generic (SKB) mode ...`)が出るので見逃さないこと。

なお veth + generic mode で受ける場合、native アタッチと違って peer の NAPI が起きないので、
live-frames 送信のフレームが黙って落ちる。受信デバイスで `ethtool -K <dev> gro on` して NAPI を
有効にする必要がある([examples/simpleudp-xdp-generic](../../examples/simpleudp-xdp-generic/) 参照)。

## veth は multi-queue にできる (コンテナ相当環境のスループット) 20260713

veth のデフォルトは 1 キューで、この場合 XDP の受信処理 (NAPI) が1コアに直列化される。
送信側の parallelism をいくら増やしても受け口が1本なので頭打ちになり、むしろ enqueue 競合で劣化する。

```shell
# 作成時にしか指定できない (既存ペアは作り直し。作成時の上限内なら ethtool -L で増減は可)
ip link add veth0 numtxqueues 8 numrxqueues 8 type veth peer name veth1 numtxqueues 8 numrxqueues 8
```

veth の ndo_xdp_xmit は送信 CPU ごとに受信キューへ振るので、multi-queue にすると
worker の並列がそのまま受信側 NAPI の並列になる。

実測 (kernel 7.2、Xeon 8362、netns ペア、xdperf 64B/1500B 片方向、受信側 recv/s):

| 構成 | 64B | 1500B |
|---|---:|---:|
| 1キュー (デフォルト)、ピーク par=2 | 7.4 Mpps | 4.6 Mpps (55Gbps) |
| 8キュー、par=16 | **61.3 Mpps (8.2倍)** | **36.7 Mpps (≈440Gbps 相当)** |

par スイープ (8キュー・64B): par2=14.9 / par4=29.8 / par8=59.5 / par16=60.9 → キュー数=8 でほぼ飽和。
キュー数にほぼ線形にスケールする。

- キュー数の上限は 4096 (veth 固有ではなく rtnetlink の汎用上限、`net/core/rtnetlink.c` の
  `num_tx_queues > 4096` チェック)。実用上の上限はコア数。
- Kubernetes 的な含意: 実際の Pod の veth はほぼ全 CNI がデフォルト 1 キューで作るため、
  Pod 間通信の XDP 性能はカーネルの限界ではなく CNI が作る veth の設定で頭打ちになっている。
  「61Mpps は現実の Pod でも出るのか?」への答えは「CNI が multi-queue veth を作れば」。
