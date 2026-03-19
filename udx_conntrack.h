#ifndef udx_conntrack_h_INCLUDED
#define udx_conntrack_h_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

typedef struct udx_flow_s udx_flow_t;

extern udx_flow_t *established[1024];

struct udx_flow_s {
    // key
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    uint32_t id;
    // end key

    int direction;

    udx_flow_t *hash_next;

    uint32_t hash_value;

    uint32_t seq;
    uint32_t ack;
    uint32_t rwnd;

    bool next_seq_valid; // set when we first see a data packet sent
    uint32_t next_seq;
    uint32_t fack;

    struct {
        uint32_t start;
        uint32_t end;
    } sacks[32];
    int nsacks;

    struct timeval start_time;
    struct timeval time;

    FILE *graph_file;
    uint64_t packets_this_second;
    uint64_t bytes_this_second;

    struct {
        int retransmits;
    } stat;
};

typedef struct {
    udx_flow_t flow[2]; // must be first item
    bool complete;      // data seen in both directions
} udx_stream_t;

udx_flow_t *
upsert_flow (struct sockaddr *src, struct sockaddr *dst, uint32_t id);

udx_stream_t *
get_stream (udx_flow_t *flow);

udx_flow_t *
get_reverse (udx_flow_t *flow);

#endif // udx_conntrack_h_INCLUDED
