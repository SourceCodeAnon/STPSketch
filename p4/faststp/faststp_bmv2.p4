/* faststp_bmv2.p4 */
#include <core.p4>
#include <v1model.p4>

const bit<32> H        = 16;
const bit<32> H_MASK   = 15;   // H-1
const bit<32> N_BUCKET = 256;
const bit<32> M_CELL   = 4;

const bit<32> D        = 2;
const bit<32> J        = 1024;

const bit<32> PERS_SZ  = N_BUCKET * M_CELL;
const bit<32> CAND_SZ  = D * J;


/* ========== Headers ========== */
typedef bit<48> mac_addr_t;

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct meta_t {
    bit<16> t;
    bit<4>  idx;       // t mod H (H=16)
    bit<16> sport;
    bit<16> dport;

    bit<32> flow_hash; // raw flow hash
    bit<32> fid;       // stored id = flow_hash + 1 (avoid 0 meaning empty)

    bit<32> b;         // bucket index 0..N_BUCKET-1

    bit<32> c0;        // candidate col row0
    bit<32> c1;        // candidate col row1
    bit<8>  pc;        // candidate estimate (Min)

    bit<32> base;      // base cell index for bucket
    bit<32> hit;       // matched cell index
    bool    found;

    bit<32> empty;     // empty cell index
    bool    has_empty;

    bit<32> min_i;     // eviction cell index
    bit<5>  pmin;

    bit<32> evict_id;
}

/* ========== Stateful memories ========== */
// control-plane writes current window t into cur_win[0]
register<bit<16>>(1) cur_win;

// Persistent Part
register<bit<32>>(PERS_SZ) pers_id;    // 0 means empty
register<bit<16>>(PERS_SZ) pers_bits;  // H=16
register<bit<5>>(PERS_SZ)  pers_s;     // popcount in [0..16]
register<bit<16>>(PERS_SZ) pers_rtw;   // last refreshed window

// Candidate Part
register<bit<8>>(CAND_SZ)  cand_cnt;   // bounded by H
register<bit<16>>(CAND_SZ) cand_ltw;

/* ========== Parser ========== */
parser MyParser(packet_in pkt,
              out headers_t hdr,
              inout meta_t meta,
              inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/* ========== No checksum for brevity ========== */
control MyVerifyChecksum(inout headers_t hdr, inout meta_t meta) { apply { } }
control MyComputeChecksum(inout headers_t hdr, inout meta_t meta) { apply { } }

/* ========== Helpers (inline via actions) ========== */
action lazy_refresh_cell(in bit<32> cell_idx, in bit<16> t) {
    bit<16> bits; bit<5> s; bit<16> last_t;
    pers_bits.read(bits, cell_idx);
    pers_s.read(s, cell_idx);
    pers_rtw.read(last_t, cell_idx);

    bit<16> delta = t - last_t;

    if (delta >= (bit<16>)H) {
        bits = 0;
        s = 0;
    } else {
        // clear positions for windows (last_t+1 .. t), up to H-1 steps
        // unrolled for H=16
        if (delta >= 1)  { bit<4> p=(bit<4>)(last_t+1);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 2)  { bit<4> p=(bit<4>)(last_t+2);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 3)  { bit<4> p=(bit<4>)(last_t+3);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 4)  { bit<4> p=(bit<4>)(last_t+4);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 5)  { bit<4> p=(bit<4>)(last_t+5);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 6)  { bit<4> p=(bit<4>)(last_t+6);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 7)  { bit<4> p=(bit<4>)(last_t+7);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 8)  { bit<4> p=(bit<4>)(last_t+8);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 9)  { bit<4> p=(bit<4>)(last_t+9);  bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 10) { bit<4> p=(bit<4>)(last_t+10); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 11) { bit<4> p=(bit<4>)(last_t+11); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 12) { bit<4> p=(bit<4>)(last_t+12); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 13) { bit<4> p=(bit<4>)(last_t+13); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 14) { bit<4> p=(bit<4>)(last_t+14); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
        if (delta >= 15) { bit<4> p=(bit<4>)(last_t+15); bit<16> m=(bit<16>)1<<p; if ((bits&m)!=0){ bits=bits & (bit<16>)(~m); s=s-1; } }
    }

    pers_bits.write(cell_idx, bits);
    pers_s.write(cell_idx, s);
    pers_rtw.write(cell_idx, t);
}

action set_bit(in bit<32> cell_idx, in bit<4> idx) {
    bit<16> bits; bit<5> s;
    pers_bits.read(bits, cell_idx);
    pers_s.read(s, cell_idx);

    bit<16> mask = (bit<16>)1 << idx;
    if ((bits & mask) == 0) {
        bits = bits | mask;
        s = s + 1;
    }
    pers_bits.write(cell_idx, bits);
    pers_s.write(cell_idx, s);
}


// ======== Candidate decay "LUT" unrolled for H=16 ========
// decayed(cnt, delta) = cnt - floor(delta * cnt / 16)
// Rules you wanted:
//   - cnt==0 or delta==0: no decay (keep)
//   - delta > H: treat as expired => decayed = 0
action cand_decay16_unrolled(in bit<8> cnt, in bit<16> delta, out bit<8> decayed) {
    decayed = cnt;

    if (cnt == 8w0)  { decayed = 8w0; return; }
    if (delta == 16w0) { return; }
    if (delta > (bit<16>)H) { decayed = 8w0; return; }

    // cnt == 1
    if (cnt == 8w1) {
        decayed = 8w1;
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 2
    else if (cnt == 8w2) {
        decayed = 8w2;
        if (delta >= 16w8)  { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 3
    else if (cnt == 8w3) {
        decayed = 8w3;
        if (delta >= 16w6)  { decayed = 8w2; }
        if (delta >= 16w11) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 4
    else if (cnt == 8w4) {
        decayed = 8w4;
        if (delta >= 16w4)  { decayed = 8w3; }
        if (delta >= 16w8)  { decayed = 8w2; }
        if (delta >= 16w12) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 5
    else if (cnt == 8w5) {
        decayed = 8w5;
        if (delta >= 16w4)  { decayed = 8w4; }
        if (delta >= 16w7)  { decayed = 8w3; }
        if (delta >= 16w10) { decayed = 8w2; }
        if (delta >= 16w13) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 6
    else if (cnt == 8w6) {
        decayed = 8w6;
        if (delta >= 16w3)  { decayed = 8w5; }
        if (delta >= 16w6)  { decayed = 8w4; }
        if (delta >= 16w8)  { decayed = 8w3; }
        if (delta >= 16w11) { decayed = 8w2; }
        if (delta >= 16w14) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 7
    else if (cnt == 8w7) {
        decayed = 8w7;
        if (delta >= 16w3)  { decayed = 8w6; }
        if (delta >= 16w5)  { decayed = 8w5; }
        if (delta >= 16w7)  { decayed = 8w4; }
        if (delta >= 16w10) { decayed = 8w3; }
        if (delta >= 16w12) { decayed = 8w2; }
        if (delta >= 16w14) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 8
    else if (cnt == 8w8) {
        decayed = 8w8;
        if (delta >= 16w2)  { decayed = 8w7; }
        if (delta >= 16w4)  { decayed = 8w6; }
        if (delta >= 16w6)  { decayed = 8w5; }
        if (delta >= 16w8)  { decayed = 8w4; }
        if (delta >= 16w10) { decayed = 8w3; }
        if (delta >= 16w12) { decayed = 8w2; }
        if (delta >= 16w14) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 9
    else if (cnt == 8w9) {
        decayed = 8w9;
        if (delta >= 16w2)  { decayed = 8w8; }
        if (delta >= 16w4)  { decayed = 8w7; }
        if (delta >= 16w6)  { decayed = 8w6; }
        if (delta >= 16w8)  { decayed = 8w5; }
        if (delta >= 16w9)  { decayed = 8w4; }
        if (delta >= 16w11) { decayed = 8w3; }
        if (delta >= 16w13) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 10
    else if (cnt == 8w10) {
        decayed = 8w10;
        if (delta >= 16w2)  { decayed = 8w9; }
        if (delta >= 16w4)  { decayed = 8w8; }
        if (delta >= 16w5)  { decayed = 8w7; }
        if (delta >= 16w7)  { decayed = 8w6; }
        if (delta >= 16w8)  { decayed = 8w5; }
        if (delta >= 16w10) { decayed = 8w4; }
        if (delta >= 16w12) { decayed = 8w3; }
        if (delta >= 16w13) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 11
    else if (cnt == 8w11) {
        decayed = 8w11;
        if (delta >= 16w2)  { decayed = 8w10; }
        if (delta >= 16w3)  { decayed = 8w9; }
        if (delta >= 16w5)  { decayed = 8w8; }
        if (delta >= 16w6)  { decayed = 8w7; }
        if (delta >= 16w8)  { decayed = 8w6; }
        if (delta >= 16w9)  { decayed = 8w5; }
        if (delta >= 16w11) { decayed = 8w4; }
        if (delta >= 16w12) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 12
    else if (cnt == 8w12) {
        decayed = 8w12;
        if (delta >= 16w2)  { decayed = 8w11; }
        if (delta >= 16w3)  { decayed = 8w10; }
        if (delta >= 16w4)  { decayed = 8w9; }
        if (delta >= 16w6)  { decayed = 8w8; }
        if (delta >= 16w7)  { decayed = 8w7; }
        if (delta >= 16w8)  { decayed = 8w6; }
        if (delta >= 16w10) { decayed = 8w5; }
        if (delta >= 16w11) { decayed = 8w4; }
        if (delta >= 16w12) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 13
    else if (cnt == 8w13) {
        decayed = 8w13;
        if (delta >= 16w2)  { decayed = 8w12; }
        if (delta >= 16w3)  { decayed = 8w11; }
        if (delta >= 16w4)  { decayed = 8w10; }
        if (delta >= 16w5)  { decayed = 8w9; }
        if (delta >= 16w7)  { decayed = 8w8; }
        if (delta >= 16w8)  { decayed = 8w7; }
        if (delta >= 16w9)  { decayed = 8w6; }
        if (delta >= 16w10) { decayed = 8w5; }
        if (delta >= 16w12) { decayed = 8w4; }
        if (delta >= 16w13) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 14
    else if (cnt == 8w14) {
        decayed = 8w14;
        if (delta >= 16w2)  { decayed = 8w13; }
        if (delta >= 16w3)  { decayed = 8w12; }
        if (delta >= 16w4)  { decayed = 8w11; }
        if (delta >= 16w5)  { decayed = 8w10; }
        if (delta >= 16w6)  { decayed = 8w9; }
        if (delta >= 16w7)  { decayed = 8w8; }
        if (delta >= 16w8)  { decayed = 8w7; }
        if (delta >= 16w10) { decayed = 8w6; }
        if (delta >= 16w11) { decayed = 8w5; }
        if (delta >= 16w12) { decayed = 8w4; }
        if (delta >= 16w13) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 15
    else if (cnt == 8w15) {
        decayed = 8w15;
        if (delta >= 16w2)  { decayed = 8w14; }
        if (delta >= 16w3)  { decayed = 8w13; }
        if (delta >= 16w4)  { decayed = 8w12; }
        if (delta >= 16w5)  { decayed = 8w11; }
        if (delta >= 16w6)  { decayed = 8w10; }
        if (delta >= 16w7)  { decayed = 8w9; }
        if (delta >= 16w8)  { decayed = 8w8; }
        if (delta >= 16w9)  { decayed = 8w7; }
        if (delta >= 16w10) { decayed = 8w6; }
        if (delta >= 16w11) { decayed = 8w5; }
        if (delta >= 16w12) { decayed = 8w4; }
        if (delta >= 16w13) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
    // cnt == 16
    else if (cnt == 8w16) {
        // 注意：delta=1 时 decayed=15（因为 floor(16*1/16)=1）
        decayed = 8w15;
        if (delta >= 16w2)  { decayed = 8w14; }
        if (delta >= 16w3)  { decayed = 8w13; }
        if (delta >= 16w4)  { decayed = 8w12; }
        if (delta >= 16w5)  { decayed = 8w11; }
        if (delta >= 16w6)  { decayed = 8w10; }
        if (delta >= 16w7)  { decayed = 8w9; }
        if (delta >= 16w8)  { decayed = 8w8; }
        if (delta >= 16w9)  { decayed = 8w7; }
        if (delta >= 16w10) { decayed = 8w6; }
        if (delta >= 16w11) { decayed = 8w5; }
        if (delta >= 16w12) { decayed = 8w4; }
        if (delta >= 16w13) { decayed = 8w3; }
        if (delta >= 16w14) { decayed = 8w2; }
        if (delta >= 16w15) { decayed = 8w1; }
        if (delta >= 16w16) { decayed = 8w0; }
    }
}


/* Candidate update for one row */
action cand_update_one(in bit<32> ridx, in bit<16> t, out bit<8> out_cnt) {
    bit<8>  cnt; 
    bit<16> ltw;
    cand_cnt.read(cnt, ridx);
    cand_ltw.read(ltw, ridx);

    // default: no update
    bit<8>  new_cnt = cnt;
    bit<16> new_ltw = ltw;

    if (ltw != t) {
        bit<16> delta = t - ltw;

        bit<8> decayed;
        cand_decay16_unrolled(cnt, delta, decayed);
        new_cnt = decayed;

        // +1 for the newly arrived packet, clamp to H
        if ((bit<32>)new_cnt < H) {
            new_cnt = new_cnt + 1;
        }
        new_ltw = t;
    }


    // IMPORTANT: unconditional writes (BMv2-friendly)
    cand_cnt.write(ridx, new_cnt);
    cand_ltw.write(ridx, new_ltw);

    out_cnt = new_cnt;
}

/* clamp cand counter >= floor */
action cand_floor(in bit<32> ridx, in bit<8> floorv) {
    bit<8> cnt;
    cand_cnt.read(cnt, ridx);

    bit<8> new_cnt = cnt;
    if (cnt < floorv) {
        new_cnt = floorv;
    }

    cand_cnt.write(ridx, new_cnt);
}

/* subtract from cand counter (saturating) */
action cand_sub_sat(in bit<32> ridx, in bit<8> sub) {
    bit<8> cnt;
    cand_cnt.read(cnt, ridx);

    bit<8> new_cnt = 0;
    if (cnt > sub) {
        new_cnt = cnt - sub;
    }

    cand_cnt.write(ridx, new_cnt);
}


/* ========== Ingress ========== */
control MyIngress(inout headers_t hdr,
                inout meta_t meta,
                inout standard_metadata_t sm) {

    apply {
        // only measure IPv4
        if (!hdr.ipv4.isValid()) { return; }

        // get current window t from register (control-plane updates it)
        cur_win.read(meta.t, 0);
        meta.idx = (bit<4>)(meta.t & (bit<16>)H_MASK);

        // ports
        meta.sport = 0; meta.dport = 0;
        if (hdr.tcp.isValid()) { meta.sport = hdr.tcp.srcPort; meta.dport = hdr.tcp.dstPort; }
        else if (hdr.udp.isValid()) { meta.sport = hdr.udp.srcPort; meta.dport = hdr.udp.dstPort; }

        // flow hash + stored id (avoid 0 as empty marker)
        hash(meta.flow_hash, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.sport, meta.dport, hdr.ipv4.protocol },
             (bit<32>)0xffffffff); // near-full range
        meta.fid = meta.flow_hash + 1;

        // bucket index
        hash(meta.b, HashAlgorithm.crc32, (bit<32>)0, { meta.fid }, (bit<32>)N_BUCKET);
        meta.base = meta.b * (bit<32>)M_CELL;

        // read ids of 4 cells
        bit<32> id0 = 0;
        bit<32> id1 = 0;
        bit<32> id2 = 0;
        bit<32> id3 = 0;
        pers_id.read(id0, meta.base + 0);
        pers_id.read(id1, meta.base + 1);
        pers_id.read(id2, meta.base + 2);
        pers_id.read(id3, meta.base + 3);

        meta.found = false;
        meta.has_empty = false;
        meta.hit = 0;
        meta.empty = 0;

        // match first
        if (id0 == meta.fid) { meta.found = true; meta.hit = meta.base + 0; }
        else if (id1 == meta.fid) { meta.found = true; meta.hit = meta.base + 1; }
        else if (id2 == meta.fid) { meta.found = true; meta.hit = meta.base + 2; }
        else if (id3 == meta.fid) { meta.found = true; meta.hit = meta.base + 3; }

        if (meta.found) {
            lazy_refresh_cell(meta.hit, meta.t);
            set_bit(meta.hit, meta.idx);
            return;
        }

        // empty slot
        if (id0 == 0) { meta.has_empty = true; meta.empty = meta.base + 0; }
        else if (id1 == 0) { meta.has_empty = true; meta.empty = meta.base + 1; }
        else if (id2 == 0) { meta.has_empty = true; meta.empty = meta.base + 2; }
        else if (id3 == 0) { meta.has_empty = true; meta.empty = meta.base + 3; }

        if (meta.has_empty) {
            pers_id.write(meta.empty, meta.fid);
            pers_bits.write(meta.empty, ((bit<16>)1 << meta.idx));
            pers_s.write(meta.empty, 1);
            pers_rtw.write(meta.empty, meta.t);
            return;
        }

        // ===== bucket full: update Candidate Part =====
        hash(meta.c0, HashAlgorithm.crc16, (bit<32>)0, { meta.fid, (bit<32>)0 }, (bit<32>)J);
        hash(meta.c1, HashAlgorithm.crc16, (bit<32>)0, { meta.fid, (bit<32>)1 }, (bit<32>)J);

        bit<32> r0 = (bit<32>)0 * (bit<32>)J + meta.c0;
        bit<32> r1 = (bit<32>)1 * (bit<32>)J + meta.c1;

        bit<8> c0v; bit<8> c1v;
        cand_update_one(r0, meta.t, c0v);
        cand_update_one(r1, meta.t, c1v);

        meta.pc = c0v;
        if (c1v < meta.pc) { meta.pc = c1v; }

        // ===== refresh all 4 cells before eviction decision =====
        lazy_refresh_cell(meta.base + 0, meta.t);
        lazy_refresh_cell(meta.base + 1, meta.t);
        lazy_refresh_cell(meta.base + 2, meta.t);
        lazy_refresh_cell(meta.base + 3, meta.t);

        bit<5> s0; bit<5> s1; bit<5> s2; bit<5> s3;
        pers_s.read(s0, meta.base + 0);
        pers_s.read(s1, meta.base + 1);
        pers_s.read(s2, meta.base + 2);
        pers_s.read(s3, meta.base + 3);

        meta.pmin = s0;
        meta.min_i = meta.base + 0;
        if (s1 < meta.pmin) { meta.pmin = s1; meta.min_i = meta.base + 1; }
        if (s2 < meta.pmin) { meta.pmin = s2; meta.min_i = meta.base + 2; }
        if (s3 < meta.pmin) { meta.pmin = s3; meta.min_i = meta.base + 3; }

        // check current-window activity bit of eviction cell
        bit<16> ebits;
        pers_bits.read(ebits, meta.min_i);
        bit<16> mask = (bit<16>)1 << meta.idx;
        bool active_now = ((ebits & mask) != 0);

        // promote if pc > pmin and eviction cell not active in current window
        if ((bit<8>)meta.pmin < meta.pc && !active_now) {
            // evicted flow id
            pers_id.read(meta.evict_id, meta.min_i);

            // push evicted back to Candidate: enforce floor = pmin
            bit<32> e_c0; bit<32> e_c1;
            hash(e_c0, HashAlgorithm.crc16, (bit<32>)0, { meta.evict_id, (bit<32>)0 }, (bit<32>)J);
            hash(e_c1, HashAlgorithm.crc16, (bit<32>)0, { meta.evict_id, (bit<32>)1 }, (bit<32>)J);
            cand_floor((bit<32>)0 * (bit<32>)J + e_c0, (bit<8>)meta.pmin);
            cand_floor((bit<32>)1 * (bit<32>)J + e_c1, (bit<8>)meta.pmin);

            // conserve budget: subtract pc from f's candidate counters
            cand_sub_sat(r0, meta.pc);
            cand_sub_sat(r1, meta.pc);

            // bit inheritance: keep ebits, ensure current bit set, then raise s to pc
            bit<5> es;
            pers_s.read(es, meta.min_i);

            if ((ebits & mask) == 0) { ebits = ebits | mask; es = es + 1; }

            // add more 1s forward until es == pc (unrolled H=16)
            // offsets 1..15
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+1);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+2);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+3);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+4);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+5);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+6);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+7);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+8);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+9);  bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+10); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+11); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+12); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+13); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+14); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }
            if (es < (bit<5>)meta.pc) { bit<4> p=(bit<4>)(meta.idx+15); bit<16> m=(bit<16>)1<<p; if((ebits&m)==0){ ebits=ebits|m;; es=es+1; } }

            // commit replacement
            pers_id.write(meta.min_i, meta.fid);
            pers_bits.write(meta.min_i, ebits);
            pers_s.write(meta.min_i, es);
            pers_rtw.write(meta.min_i, meta.t);
        }

        if (sm.ingress_port == 1)      { sm.egress_spec = 2; }
        else if (sm.ingress_port == 2) { sm.egress_spec = 1; }
        else                           { sm.egress_spec = sm.ingress_port; }

    }
}

control MyEgress(inout headers_t hdr, inout meta_t meta, inout standard_metadata_t sm) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}


V1Switch(MyParser(),
         MyVerifyChecksum(),
         MyIngress(),
         MyEgress(),
         MyComputeChecksum(),
         MyDeparser()) main;

// p4c --std p4-16 --target bmv2 --arch v1model -o ~/stpsketch/behavioral-model/build ~/stpsketch/faststp/faststp_bmv2.p4