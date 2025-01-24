#ifndef all_h_INCLUDED
#define all_h_INCLUDED

#include <stdint.h>

typedef struct {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ether_type;
} eth_hdr_t;

// DLT_LINUX_SLL2 header
// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
// used when you capture 'any' device on some linuxes
typedef struct {
    uint16_t protocol_type;
    uint16_t reserved;
    int32_t interface_index;
    uint16_t arphrd_type;
    uint8_t packet_type;
    uint8_t link_layer_addrlen;
    uint8_t link_layer_addr[8];
} sll_hdr_t;

typedef struct {
    uint8_t v_and_hl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
    // options start
} ip4_hdr_t;

typedef struct {
    uint32_t flow; // 4 bits version, 8 bits tc, 20 bits flow id
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
} ip6_hdr_t;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} udp_hdr_t;

typedef struct {
    uint8_t magic;
    uint8_t data_offset;
} udx_hdr_t;

typedef struct {
    uint32_t seq;
    uint32_t ack;
    uint16_t size;
    uint16_t transmits;
    uint64_t timestamp_millis;
} udx_packet_t;

// cirbuf

typedef struct {
    uint32_t size;
    uint32_t mask;
    udx_packet_t **values;
} udx_cirbuf_t;

void
udx__cirbuf_init (udx_cirbuf_t *c, uint32_t initial_size);

void
udx__cirbuf_destroy (udx_cirbuf_t *c);

void
udx__cirbuf_set (udx_cirbuf_t *c, udx_packet_t *val);

udx_packet_t *
udx__cirbuf_get (udx_cirbuf_t *c, uint32_t seq);

udx_packet_t *
udx__cirbuf_remove (udx_cirbuf_t *c, uint32_t seq);

#endif // all_h_INCLUDED
