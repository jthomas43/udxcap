#ifndef all_h_INCLUDED
#define all_h_INCLUDED

#include <stdint.h>

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
