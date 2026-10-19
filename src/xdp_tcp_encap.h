#ifndef XDP_TCP_ENCAP_H
#define XDP_TCP_ENCAP_H

// Separate from the base collection's frozen rodata. The host specializes only
// builders; RX parsing still accepts asymmetric return paths.
const volatile __u32 mixed_max_lengths SEC(".rodata.mixed") = 8;
const volatile __u32 mixed_max_outer_ips SEC(".rodata.mixed") = 4;
const volatile __u32 mixed_max_udps SEC(".rodata.mixed") = 4;
const volatile __u32 mixed_has_lco SEC(".rodata.mixed") = 1;

// Outer headers use a validated fixup table, independent of tunnel protocol.
static __noinline int tcp_encap_patch(struct xdp_md *ctx, const struct tcp_template *t, __u32 tcp_len, __u32 flow, __u16 ip_id)
{
    __u8 *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (t->length_count > 8 || t->outer_ip_count > 4 || t->udp_count > 4)
        return -1;
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i < mixed_max_lengths && i < t->length_count) {
            __u32 off = t->lengths[i].offset;
            __u32 value = t->lengths[i].constant + tcp_len;
            if (off > 254 || value > 65535 || (void *)(data + off + 2) > end)
                return -1;
            put_be16(data + off, value);
        }
    }
    __u32 entropy = t->entropy_offset;
    if (t->entropy_count) {
        if (entropy > 248 || (void *)(data + entropy + 8) > end)
            return -1;
        put_be16(data + entropy, t->entropy_base + flow % t->entropy_count);
    }
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (i < mixed_max_outer_ips && i < t->outer_ip_count) {
            __u32 off = t->outer_ips[i].offset;
            if (off > 216)
                return -1;
            __u8 ih[20];
            if (bpf_xdp_load_bytes(ctx, off, ih, 20) < 0)
                return -1;
            if (t->outer_ips[i].version == 4) {
                ih[1] &= 0xfc;
                if (t->cfg.ip_id_shared)
                    put_be16(ih + 4, ip_id);
                ih[10] = ih[11] = 0;
                __u64 sum = 0;
                SUM16_BUF(sum, ih, 20);
                put_be16(ih + 10, tcp_csum_fold(sum));
            } else {
                ih[1] &= 0xcf;
            }
            if (bpf_xdp_store_bytes(ctx, off, ih, 20) < 0)
                return -1;
        }
    }
    data = (void *)(long)ctx->data;
    end = (void *)(long)ctx->data_end;
    // Innermost UDP first: outer UDP includes the already final inner checksum.
#pragma unroll
    for (int i = 3; i >= 0; i--) {
        if (i < mixed_max_udps && i < t->udp_count) {
            __u32 off = t->udps[i].offset;
            __u32 l4 = t->cfg.l4_off;
            if (off > 248 || l4 > 236 || l4 < off + 8 || (void *)(data + off + 8) > end)
                return -1;
            data[off + 6] = data[off + 7] = 0;
            if (mixed_has_lco && t->udps[i].mode) {
                __u32 udp_len = l4 - off + tcp_len;
                __u64 sum = t->udps[i].pseudo_sum + IPPROTO_UDP + udp_len;
                // A valid inner TCP segment sums to the complement of its
                // pseudo header. This remains true for odd payload lengths.
                __u16 inner = tcp_csum_fold(t->cfg.pseudo_sum + IPPROTO_TCP + tcp_len);
                if ((l4 - off) & 1)
                    inner = (inner >> 8) | (inner << 8);
                sum += inner;
#pragma unroll
                for (int j = 0; j < 256; j += 2) {
                    if (j < l4 - off) {
                        __u32 at = off + j;
                        if (at > 255 || (void *)(data + at + 1) > end)
                            return -1;
                        __u16 word = (__u16)data[at] << 8;
                        if (j + 1 < l4 - off) {
                            if ((void *)(data + at + 2) > end)
                                return -1;
                            word |= data[at + 1];
                        }
                        sum += word;
                    }
                }
                __u16 check = tcp_csum_fold(sum);
                put_be16(data + off + 6, check ? check : 0xffff);
            }
        }
    }
    return 0;
}
#endif
