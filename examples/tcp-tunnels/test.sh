#!/bin/bash
# TCP through Linux GRE, IPIP, SRv6 and MPLS endpoints.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
prepare_tcp_plugin_test
srcmac="$(ip netns exec "$NS_TX" cat "/sys/class/net/${VETH_TX}/address")"
dstmac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
# Permanent underlay neighbours isolate tunnel parsing from discovery timing.
ip -n "$NS_RX" neigh replace "$TX_IP4" lladdr "$srcmac" dev "$VETH_RX"
ip -n "$NS_RX" -6 neigh replace "$TX_IP6" lladdr "$srcmac" dev "$VETH_RX"
completed=0
for kind in ${TUNNEL_CASES:-gre gre-key gretap ip6gre ipip ip6tnl srv6 srv6-two srv6-bare mpls gtpu}; do
    modules=()
    case "$kind" in
        gre|gre-key|gretap) modules=(ip_gre);;
        ip6gre) modules=(ip6_gre);;
        ipip) modules=(ipip sit);;
        ip6tnl) modules=(ip6_tunnel);;
        mpls) modules=(mpls_router mpls_iptunnel);;
        gtpu) modules=(gtp);;
    esac
    available=true
    for module in "${modules[@]}"; do
        if ! modprobe "$module" && [ ! -d "/sys/module/$module" ]; then
            print_info "SKIP $kind: kernel module $module unavailable; use TestTCPReceiveTunnels"
            available=false
        fi
    done
    if [ "$available" = false ]; then continue; fi
    if [[ "$kind" = srv6* ]] && ! ip netns exec "$NS_RX" test -e /proc/sys/net/ipv6/conf/all/seg6_enabled; then
        print_info "SKIP $kind: kernel SEG6 unavailable; use TestTCPReceiveTunnels"
        continue
    fi
    if [ "$kind" = gtpu ]; then
        if ! ip -n "$NS_RX" link add gtp-probe type gtp role ggsn; then
            print_info "SKIP gtpu: kernel/iproute2 lacks kernel-owned GTP sockets; use TestTCPReceiveTunnels"
            continue
        fi
        ip -n "$NS_RX" link del gtp-probe
    fi
    for inner in ${INNER_CASES:-4 6}; do
        osrc="$TX_IP4"; odst="$RX_IP4"
        case "$kind" in ip6gre|ip6tnl|srv6*) osrc="$TX_IP6"; odst="$RX_IP6";; esac
        isrc=192.168.120.1; idst=192.168.120.2; prefix=24; family=-4
        if [ "$inner" = 6 ]; then isrc=fd00:120::1; idst=fd00:120::2; prefix=64; family=-6; fi
        ism="$srcmac"; idm="$dstmac"
        for side in tx rx; do
            if [ "$side" = tx ]; then ns="$NS_TX"; dev="$VETH_TX"; local_ip="$osrc"; remote="$odst"; hostip="$isrc"; peer="$idst"; else ns="$NS_RX"; dev="$VETH_RX"; local_ip="$odst"; remote="$osrc"; hostip="$idst"; peer="$isrc"; fi
            ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
            ip netns exec "$ns" sysctl -qw "net.ipv4.conf.${dev}.rp_filter=0"
            case "$kind" in
                gre|gre-key|gretap|ip6gre)
                    type="$kind"; args=(); if [ "$kind" = gre-key ]; then type=gre; args=(key 7); fi
                    if [ "$kind" = ip6gre ]; then args=(encaplimit none); fi
                    ip -n "$ns" link add tun7 type "$type" local "$local_ip" remote "$remote" dev "$dev" "${args[@]}"
                    ;;
                ipip)
                    if [ "$inner" = 6 ]; then type=sit; else type=ipip; fi
                    ip -n "$ns" link add tun7 type "$type" local "$local_ip" remote "$remote" dev "$dev"
                    ;;
                ip6tnl)
                    ip -n "$ns" link add tun7 type ip6tnl mode any encaplimit none local "$local_ip" remote "$remote" dev "$dev"
                    ;;
                srv6*)
                    ip -n "$ns" link add tun7 type dummy
                    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
                    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.seg6_enabled=1
                    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.${dev}.seg6_enabled=1"
                    ;;
                gtpu)
                    if [ "$side" = rx ]; then
                        ip -n "$ns" link add tun7 type gtp role ggsn
                    else
                        ip -n "$ns" link add tun7 type dummy
                    fi
                    ;;
                mpls)
                    ip -n "$ns" link add tun7 type dummy
                    ip netns exec "$ns" sysctl -qw net.mpls.platform_labels=256
                    ip netns exec "$ns" sysctl -qw "net.mpls.conf.${dev}.input=1"
                    label=100; if [ "$side" = rx ]; then label=200; fi
                    ip -n "$ns" -f mpls route add "$label" dev lo
                    ;;
            esac
            ip -n "$ns" link set tun7 up
            addr_args=(); if [ "$inner" = 6 ]; then addr_args=(nodad); fi
            ip -n "$ns" "$family" addr add "$hostip/$prefix" dev tun7 "${addr_args[@]}"
        done
        if [ "$kind" = gretap ]; then
            ism="$(ip netns exec "$NS_TX" cat /sys/class/net/tun7/address)"
            idm="$(ip netns exec "$NS_RX" cat /sys/class/net/tun7/address)"
            ip -n "$NS_RX" "$family" neigh replace "$isrc" lladdr "$ism" dev tun7
        fi
        if [ "$kind" = gtpu ]; then
            rc=0
            ip netns exec "$NS_RX" python3 "$SCRIPT_DIR/gtp_context.py" tun7 "$osrc" "$isrc" || rc=$?
            if [ "$rc" -eq 3 ]; then
                ip -n "$NS_TX" link del tun7
                ip -n "$NS_RX" link del tun7
                continue
            elif [ "$rc" -ne 0 ]; then
                exit "$rc"
            fi
        fi
        case "$kind" in
            srv6*)
                # A local SID decapsulates to the kernel TCP endpoint.
                odst=fd00:777::2
                if [ "$inner" = 4 ]; then
                    ip -n "$NS_RX" -6 route add "$odst/128" encap seg6local action End.DX4 nh4 0.0.0.0 dev tun7
                else
                    ip -n "$NS_RX" -6 route add "$odst/128" encap seg6local action End.DT6 table 255 dev tun7
                fi
                hostprefix=32; if [ "$inner" = 6 ]; then hostprefix=128; fi
                if [ "$kind" = srv6-bare ]; then
                    if [ "$inner" = 4 ]; then via="$TX_IP4"; else via="$TX_IP6"; fi
                    ip -n "$NS_RX" "$family" route add "$isrc/$hostprefix" via "$via" dev "$VETH_RX"
                else
                    segs="$TX_IP6"; if [ "$kind" = srv6-two ]; then segs="$TX_IP6,$RX_IP6"; fi
                    ip -n "$NS_RX" "$family" route add "$isrc/$hostprefix" encap seg6 mode encap segs "$segs" dev "$VETH_RX"
                fi
                ;;
            mpls)
                hostprefix=32; via="$TX_IP4"; if [ "$inner" = 6 ]; then hostprefix=128; via="$TX_IP6"; fi
                ip -n "$NS_RX" "$family" route add "$isrc/$hostprefix" encap mpls 100 via "$via" dev "$VETH_RX"
                ;;
        esac
        endpoint="${idst}:${DST_PORT}"; if [ "$inner" = 6 ]; then endpoint="[${idst}]:${DST_PORT}"; fi
        start_sink "$endpoint"
        config="$(python3 "${TCP_PY_DIR}/config.py" tunnel "$kind" "$srcmac" "$dstmac" "$osrc" "$odst" "$isrc" "$idst" "$ism" "$idm" "$DST_PORT")"
        report="${XDPERF_EXAMPLE_RUNDIR}/tunnel-${kind}-${inner}.csv"
        TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/tunnel-${kind}-${inner}.log"
        run_tcp_plugin "$config" "$report" --recv --count 128 --pps 4000 --parallelism 1
        stop_sink
        python3 "${TCP_PY_DIR}/verify.py" tunnel "$report" "$SINK_LOG" "$TX_LOG"
        completed=$((completed + 1))
        print_success "TCP ${kind}, inner IPv${inner}: flows/bytes verified"
        ip -n "$NS_TX" link del tun7
        ip -n "$NS_RX" link del tun7
        # Routes using the underlay persist after deleting the tunnel.
        ip -n "$NS_RX" "$family" route del "$isrc/$(if [ "$inner" = 4 ]; then echo 32; else echo 128; fi)" 2>/dev/null || true
        if [ "$kind" = mpls ]; then
            ip -n "$NS_TX" -f mpls route del 100
            ip -n "$NS_RX" -f mpls route del 200
        fi
    done
done

if [ "$completed" -eq 0 ]; then
    print_info "SKIP: no Linux tunnel cases available; use TestTCPReceiveTunnels"
    exit "$SKIP_EXIT_CODE"
fi
