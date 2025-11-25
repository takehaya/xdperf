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
