// SPDX-License-Identifier: MIT
/*
 * xdperf plugin in C: VXLAN with a fixed outer 5-tuple and a configurable
 * number of inner UDP flows. Built freestanding for wasm32 (no libc, no WASI);
 * the packet layout comes from vxlan_shared.h, which BPF code can include too.
 *
 * ABI (same as the TinyGo plugins): plugin_init/process/cleanup take
 * (in_ptr, in_len, out_ptr, out_cap), read a JSON request and write a JSON
 * response, returning its length (negative on error). malloc/free let the
 * host place the buffers.
 */
#include "vxlan_shared.h"

typedef __SIZE_TYPE__ size_t;
typedef __UINT64_TYPE__ u64;

#define EXPORT(name) __attribute__((export_name(name)))
#define IMPORT(mod, name) __attribute__((import_module(mod), import_name(name)))

IMPORT("env", "host_log") void host_log(vx_u32 level, const char *msg, vx_u32 len);

/* ---- memory: a bump allocator; the host frees in LIFO order per call ---- */
extern unsigned char __heap_base;
static size_t heap_top;

void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *dp = d;
    const unsigned char *sp = s;
    while (n--)
        *dp++ = *sp++;
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *dp = d;
    while (n--)
        *dp++ = (unsigned char)c;
    return d;
}

EXPORT("malloc") void *malloc(size_t n)
{
    if (!heap_top)
        heap_top = (size_t)&__heap_base;
    size_t p = (heap_top + 15) & ~(size_t)15;
    size_t end = p + n;
    size_t have = __builtin_wasm_memory_size(0) * 65536;
    if (end > have && __builtin_wasm_memory_grow(0, (end - have + 65535) / 65536) == (size_t)-1)
        return 0;
    heap_top = end;
    return (void *)p;
}

/* Every call frees what it allocated, so rewinding to the freed block is enough. */
EXPORT("free") void free(void *p)
{
    if (p && (size_t)p < heap_top)
        heap_top = (size_t)p;
}

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static void logs(vx_u32 level, const char *s)
{
    host_log(level, s, slen(s));
}

/* ---- minimal JSON reading: flat objects of numbers and strings ---- */
static int json_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static const char *json_find(const char *j, size_t n, const char *key)
{
    size_t k = slen(key);
    for (size_t i = 0; i < n; i++) {
        if (j[i] != '"')
            continue;
        size_t start = ++i;
        /* Skip the whole string, including escaped quotes in values. */
        while (i < n && j[i] != '"') {
            if (j[i] == '\\' && i + 1 < n)
                i++;
            i++;
        }
        if (i == n || i - start != k)
            continue;
        size_t m = 0;
        while (m < k && j[start + m] == key[m])
            m++;
        if (m != k)
            continue;
        size_t p = i + 1;
        while (p < n && json_space(j[p]))
            p++;
        /* A matching string value is not a key. Keep looking. */
        if (p == n || j[p] != ':')
            continue;
        p++;
        while (p < n && json_space(j[p]))
            p++;
        return p < n ? j + p : 0;
    }
    return 0;
}

static u64 json_uint(const char *j, size_t n, const char *key, u64 def)
{
    const char *p = json_find(j, n, key);
    if (!p)
        return def;
    /* No supported option accepts UINT64_MAX; use it to signal invalid input. */
    if (*p < '0' || *p > '9')
        return ~(u64)0;
    u64 v = 0;
    while (p < j + n && *p >= '0' && *p <= '9') {
        u64 digit = (u64)(*p++ - '0');
        if (v > (~(u64)0 - digit) / 10)
            return ~(u64)0;
        v = v * 10 + digit;
    }
    if (p < j + n && *p != ',' && *p != '}' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
        return ~(u64)0;
    return v;
}

/* Copies the string value of key into out (NUL-terminated); 0 if absent. */
static int json_str(const char *j, size_t n, const char *key, char *out, size_t cap)
{
    const char *p = json_find(j, n, key);
    if (!p || *p != '"')
        return 0;
    p++;
    size_t i = 0;
    while (p < j + n && *p != '"' && i + 1 < cap)
        out[i++] = *p++;
    out[i] = 0;
    return p < j + n && *p == '"';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_mac(const char *s, vx_u8 mac[6])
{
    if (slen(s) != 17)
        return 0;
    for (int i = 0; i < 6; i++) {
        int hi = hexval(s[i * 3]), lo = hexval(s[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && s[i * 3 + 2] != ':'))
            return 0;
        mac[i] = (vx_u8)(hi << 4 | lo);
    }
    return 1;
}

/* Dotted quad to a network-order address stored as bytes. */
static int parse_ip4(const char *s, vx_u8 ip[4])
{
    for (int i = 0; i < 4; i++) {
        unsigned v = 0, digits = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s++ - '0');
            if (v > 255)
                return 0;
            digits++;
        }
        if (!digits || v > 255 || (i < 3 && *s++ != '.'))
            return 0;
        ip[i] = (vx_u8)v;
    }
    return *s == 0;
}

static int cfg_mac(const char *j, size_t n, const char *key, vx_u8 mac[6])
{
    char buf[32];
    return json_str(j, n, key, buf, sizeof(buf)) && parse_mac(buf, mac);
}

static int cfg_ip4(const char *j, size_t n, const char *key, vx_u8 ip[4])
{
    char buf[32];
    return json_str(j, n, key, buf, sizeof(buf)) && parse_ip4(buf, ip);
}

/* ---- packet building ---- */
static void put16(vx_u8 *p, vx_u16 v)
{
    p[0] = (vx_u8)(v >> 8);
    p[1] = (vx_u8)v;
}

static vx_u16 ip4_csum(const vx_u8 *h)
{
    vx_u32 s = 0;
    for (int i = 0; i < VX_IP4_LEN; i += 2)
        s += (vx_u32)h[i] << 8 | h[i + 1];
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (vx_u16)~s;
}

static void build_ip4(vx_u8 *h, vx_u16 total, const vx_u8 src[4], const vx_u8 dst[4])
{
    memset(h, 0, VX_IP4_LEN);
    h[0] = 0x45;
    put16(h + 2, total);
    h[8] = 64;
    h[9] = 17; /* UDP */
    memcpy(h + 12, src, 4);
    memcpy(h + 16, dst, 4);
    put16(h + 10, ip4_csum(h));
}

static void build_udp(vx_u8 *h, vx_u16 sport, vx_u16 dport, vx_u16 len)
{
    put16(h, sport);
    put16(h + 2, dport);
    put16(h + 4, len);
    put16(h + 6, 0); /* optional over IPv4; VXLAN sends 0 */
}

/* ---- JSON writing ---- */
struct out {
    char *p;
    size_t len, cap;
};

static void emit(struct out *o, const char *s)
{
    while (*s && o->len < o->cap)
        o->p[o->len++] = *s++;
}

static void emit_uint(struct out *o, u64 v)
{
    char b[24];
    int i = 0;
    do
        b[i++] = (char)('0' + v % 10);
    while (v /= 10);
    while (i && o->len < o->cap)
        o->p[o->len++] = b[--i];
}

static void emit_b64(struct out *o, const vx_u8 *d, size_t n)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < n; i += 3) {
        vx_u32 v = (vx_u32)d[i] << 16;
        if (i + 1 < n)
            v |= (vx_u32)d[i + 1] << 8;
        if (i + 2 < n)
            v |= d[i + 2];
        char c[5] = {t[v >> 18 & 63], t[v >> 12 & 63], i + 1 < n ? t[v >> 6 & 63] : '=', i + 2 < n ? t[v & 63] : '=', 0};
        emit(o, c);
    }
}

static int finish(struct out *o)
{
    return o->len < o->cap ? (int)o->len : -4;
}

/* ---- exports ---- */
EXPORT("plugin_init") int plugin_init(const char *in, vx_u32 in_len, char *out, vx_u32 cap)
{
    (void)in;
    (void)in_len;
    logs(1, "vxlan.c plugin initialized");
    struct out o = {out, 0, cap};
    emit(&o, "{\"success\":true}");
    return finish(&o);
}

EXPORT("plugin_cleanup") int plugin_cleanup(const char *in, vx_u32 in_len, char *out, vx_u32 cap)
{
    (void)in;
    (void)in_len;
    struct out o = {out, 0, cap};
    emit(&o, "{\"success\":true}");
    return finish(&o);
}

/*
 * Config keys: src_mac, dst_mac, src_ip, dst_ip (outer); src_port (outer UDP
 * source, fixed: default 49152); vni (default 100); inner_src_ip,
 * inner_dst_ip; inner_dport (default 5000); inner_sport_base (default 10000);
 * inner_flows (default 1): the inner UDP source port sweeps
 * inner_sport_base .. +inner_flows-1 while the outer headers stay fixed;
 * payload (inner UDP payload bytes, default 18).
 */
EXPORT("plugin_process") int plugin_process(const char *in, vx_u32 n, char *out, vx_u32 cap)
{
    vx_u8 smac[6], dmac[6], sip[4], dip[4], isip[4], idip[4];
    if (!cfg_mac(in, n, "src_mac", smac) || !cfg_mac(in, n, "dst_mac", dmac) || !cfg_ip4(in, n, "src_ip", sip) ||
        !cfg_ip4(in, n, "dst_ip", dip) || !cfg_ip4(in, n, "inner_src_ip", isip) || !cfg_ip4(in, n, "inner_dst_ip", idip)) {
        logs(3, "vxlan.c: src_mac, dst_mac, src_ip, dst_ip, inner_src_ip and inner_dst_ip are required");
        return -5;
    }
    u64 vni = json_uint(in, n, "vni", 100);
    u64 oport = json_uint(in, n, "src_port", 49152);
    u64 idport = json_uint(in, n, "inner_dport", 5000);
    u64 base = json_uint(in, n, "inner_sport_base", 10000);
    u64 flows = json_uint(in, n, "inner_flows", 1);
    u64 payload = json_uint(in, n, "payload", 18);
    if (vni > 0xFFFFFF || oport > 0xFFFF || idport > 0xFFFF || base > 0xFFFF || !flows || flows > 0x10000 ||
        base + flows - 1 > 0xFFFF || payload > 1400) {
        logs(3, "vxlan.c: value out of range");
        return -6;
    }

    vx_u8 pkt[1500];
    size_t inner_len = VX_INNER_L4_OFF + VX_UDP_LEN + payload;
    size_t total = VX_OUTER_LEN + inner_len;
    memset(pkt, 0, total);

    /* outer */
    memcpy(pkt, dmac, 6);
    memcpy(pkt + 6, smac, 6);
    put16(pkt + 12, 0x0800);
    vx_u8 *oip = pkt + VX_ETH_LEN;
    build_ip4(oip, (vx_u16)(total - VX_ETH_LEN), sip, dip);
    build_udp(oip + VX_IP4_LEN, (vx_u16)oport, VXLAN_UDP_PORT, (vx_u16)(VX_UDP_LEN + VX_HDR_LEN + inner_len));
    vxlan_set_vni((struct vxlan_hdr *)(oip + VX_IP4_LEN + VX_UDP_LEN), (vx_u32)vni);

    /* inner Ethernet + IPv4 + UDP */
    vx_u8 *inner = pkt + VX_OUTER_LEN;
    const vx_u8 imac_s[6] = {0x02, 0, 0, 0, 0, 1}, imac_d[6] = {0x02, 0, 0, 0, 0, 2};
    memcpy(inner, imac_d, 6);
    memcpy(inner + 6, imac_s, 6);
    put16(inner + 12, 0x0800);
    build_ip4(inner + VX_INNER_IP_OFF, (vx_u16)(inner_len - VX_ETH_LEN), isip, idip);
    build_udp(inner + VX_INNER_L4_OFF, (vx_u16)base, (vx_u16)idport, (vx_u16)(VX_UDP_LEN + payload));

    struct out o = {out, 0, cap};
    emit(&o, "{\"template_type\":\"variable\",\"variable_packet_template\":{\"pattern\":\"sequential\",\"variants\":[{\"weight\":1,"
             "\"base_packet\":{\"length\":");
    emit_uint(&o, total);
    emit(&o, ",\"data\":\"");
    emit_b64(&o, pkt, total);
    emit(&o, "\"},\"variable_params\":[");
    if (flows > 1) {
        emit(&o, "{\"byte_start\":");
        emit_uint(&o, VX_OUTER_LEN + VX_INNER_L4_OFF);
        emit(&o, ",\"byte_size\":2,\"pattern_type\":\"sequential\",\"byte_range\":{\"start\":");
        emit_uint(&o, base);
        emit(&o, ",\"end\":");
        emit_uint(&o, base + flows - 1);
        emit(&o, "}}");
    }
    emit(&o, "]}]}}");
    return finish(&o);
}
