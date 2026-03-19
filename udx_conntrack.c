#include "udx_conntrack.h"
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// this module tracks udx connections
// each connection is made of two flows, going
// in opposite directions.
// a flow can be identified by a 5 tuple of
// src_ip:src_port:dst_ip:dst_port:dst_id

// Algorithm: matching a packet to a stream
// keep two tables for flows - 'established' and 'new'
// the 'established' table is keyed by the 5-tuple src_ip:src_port:dst_ip:dst_port:dst_id
// the 'new' table is keyed by the 4-typle src_ip:srd_port:dst_ip:dst_port
// for each packet
//     lookup a flow in the established table with the 5tuple
//     if found:
//         the stream may be found with the container_of macro. DONE
//     else:
//         lookup a flow in the new table with the 4tuple
//         if found:
//             if the flow's id matches:
//                 we've seen this direction, update seq, ack, etc. DONE.
//             else:
//                 we've found the reverse direction *
//                 label it complete
//                 remove both flows and insert them into the 5tuple table
//                 DONE
//         else:
//             we've never seen this flow (forward or reverse).
//             create a stream, create a forward and reverse flow (leave reverse id=0)
//             label the reverse flow incomplete
//             DONE
// * there's ambiguity here - we don't know for if the stream coming in the other
// direction is the response stream - even if the seq and acks match it could be a previously
// unseen stream with an unseen pair. unlike UDP / TCP we can only make a best guess

udx_flow_t *new[1024];
udx_flow_t *established[1024];

#define FNV_32_PRIME ((uint32_t) 0x01000193)

// fnv32 hash - licensed public domain
static uint32_t
hash (void *buf, size_t len, uint32_t hval) {

    uint8_t *p = (uint8_t *) buf;
    uint8_t *last = p + len;

    while (p < last) {
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
        hval ^= (uint32_t) *p++;
    }

    return hval;
}

static size_t
addr_sizeof (struct sockaddr *sa) {
    assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);
    return sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static uint32_t
hash_sockaddr (struct sockaddr *sa, uint32_t h) {
    return hash(sa, addr_sizeof(sa), h);
}

#define ARRAY_SIZEOF(a)                    (sizeof((a)) / sizeof((a)[0]))
#define container_of(pointer, type, field) ((type *) ((char *) (pointer) - offsetof(type, field)))

static bool
addr_equal (struct sockaddr *a, struct sockaddr *b) {
    if (a->sa_family != b->sa_family) return false;

    if (a->sa_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *) a;
        struct sockaddr_in *sb = (struct sockaddr_in *) b;
        return sa->sin_port == sb->sin_port && memcmp(&sa->sin_addr, &sb->sin_addr, sizeof(sa->sin_addr)) == 0;
    } else {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) a;
        struct sockaddr_in6 *sb = (struct sockaddr_in6 *) b;
        return sa->sin6_port == sb->sin6_port && memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr)) == 0;
    };
}

// we return a ** instead of the typical * because the
// ** API allows a user to lookup / insert / remove
// lookup: flow = *lookup_4tuple(src, dst)
// insert: *lookup_4tuple(src, dst) = calloc(...)
// remove: pf = lookup_4tuple(src, dst); *pf =  (*pf)->hash_next;
udx_flow_t **
lookup_4tuple (struct sockaddr *src, struct sockaddr *dst) {
    uint32_t h = 0;

    h = hash_sockaddr(src, h);
    h = hash_sockaddr(dst, h);

    int index = h & (ARRAY_SIZEOF(new) - 1);

    udx_flow_t **chain = &new[index];

    while ((*chain) != NULL) {
        if (addr_equal(src, (struct sockaddr *) &(*chain)->src) && addr_equal(dst, (struct sockaddr *) &(*chain)->dst)) {
            break;
        }
        chain = &(*chain)->hash_next;
    }

    return chain;
}
udx_flow_t **
lookup_5tuple (struct sockaddr *src, struct sockaddr *dst, uint32_t id) {
    uint32_t h = 0;

    h = hash_sockaddr(src, h);
    h = hash_sockaddr(dst, h);
    h = hash(&id, sizeof(id), h);

    int index = h & (ARRAY_SIZEOF(established) - 1);
    udx_flow_t **chain = &established[index];

    while (*chain != NULL) {
        if (addr_equal(src, (struct sockaddr *) &(*chain)->src) && addr_equal(dst, (struct sockaddr *) &(*chain)->dst)) {
            break;
        }
        chain = &(*chain)->hash_next;
    }

    return chain;
}

bool debug = false;

udx_flow_t *
upsert_flow (struct sockaddr *src, struct sockaddr *dst, uint32_t id) {

    udx_flow_t **pp = lookup_5tuple(src, dst, id);

    if (*pp) {
        return *pp;
    }

    pp = lookup_4tuple(src, dst);

    if (*pp) {
        if ((*pp)->direction == 0) {
            return *pp;
        } else {
            assert((*pp)->direction == 1);
            assert((*pp)->id == 0);
            // found sibling (reverse) flow
            udx_flow_t *f1 = *pp;
            f1->id = id;
            udx_flow_t *f0 = f1 - 1; // sibling is always second
            udx_stream_t *stream = get_stream(f0);
            // remove ourselves
            *pp = (*pp)->hash_next;
            pp = lookup_4tuple(dst, src);
            assert(*pp == f0);
            *pp = (*pp)->hash_next;
            // insert into the 5tuple table

            *lookup_5tuple((struct sockaddr *) &f0->src, (struct sockaddr *) &f0->dst, f0->id) = f0;
            *lookup_5tuple((struct sockaddr *) &f1->src, (struct sockaddr *) &f1->dst, f1->id) = f1;

            stream->complete = true;

            return f1;
        }
    } else {
        // no flow in 4tuple
        udx_stream_t *s = calloc(1, sizeof(*s));

        udx_flow_t *f0 = &s->flow[0];
        memcpy(&f0->src, src, addr_sizeof(src));
        memcpy(&f0->dst, dst, addr_sizeof(dst));
        f0->direction = 0;
        f0->id = id;

        udx_flow_t *f1 = &s->flow[1];
        memcpy(&f1->src, dst, addr_sizeof(dst));
        memcpy(&f1->dst, src, addr_sizeof(src));
        f1->direction = 1;

        *pp = f0;
        pp = lookup_4tuple(dst, src);
        assert(*pp == NULL);
        *pp = f1;

        return f0;
    }
}

udx_stream_t *
get_stream (udx_flow_t *flow) {
    if (flow->direction == 0) {
        return container_of(flow, udx_stream_t, flow);
    } else {
        return container_of(flow - 1, udx_stream_t, flow);
    }
}

udx_flow_t *
get_reverse (udx_flow_t *flow) {
    if (flow->direction == 0) {
        return flow + 1;
    } else {
        return flow - 1;
    }
}
