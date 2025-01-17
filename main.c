
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "all.h"

// todo:
// 1.measure rtt. trickier than you might expect,
// with tcp it's the time for sending SYN, receiving SYN+ACK, and then sending ACK
// simply measuring from DATA to ACK is not enough, if we're on capturing host that's receiving
// that only measures the time spent processing
// technique: measure the time between the first DATA packet and the 11th data packet

struct sockaddr_storage source;
struct sockaddr_storage dest;

char source_name[INET6_ADDRSTRLEN];
char dest_name[INET6_ADDRSTRLEN];

struct iphdr *ip;
struct ip6_hdr *ip6;
struct udphdr *udp;
struct ethhdr *eth;

// output is grouped into triplets of lines: a prefix, the line itself, and a suffix.
// output_prefix(), output(), and output_suffix() are used to write to these buffers.
char line_buf[0x4000];
char *line;
int linelen;

char prefix_buf[0x4000];
char *prefix;
int prefixlen;

char suffix_buf[0x4000];
char *suffix;
int suffixlen;

struct {
    bool print_packet_bytes;
} opts;

void
output (char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    linelen += vsnprintf(line, sizeof(line_buf) - linelen, fmt, ap);
    line = line_buf + linelen;

    va_end(ap);
}

void
output_prefix (char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    prefixlen += vsnprintf(prefix, sizeof(prefix_buf) - prefixlen, fmt, ap);
    prefix = prefix_buf + prefixlen;

    va_end(ap);
}

void
output_suffix (char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    suffixlen += vsnprintf(suffix, sizeof(suffix_buf) - suffixlen, fmt, ap);
    suffix = suffix_buf + suffixlen;

    va_end(ap);
}

void
final_output () {
    if (prefixlen) {
        printf("%.*s\n", prefixlen, prefix_buf);
    }

    if (linelen) {
        printf("%.*s\n", linelen, line_buf);
    }

    if (suffixlen) {
        printf("%.*s\n", suffixlen, suffix_buf);
    }
    prefixlen = 0;
    linelen = 0;
    suffixlen = 0;
}

typedef struct udx_stream_s udx_stream_t;
typedef struct udx_flow_s udx_flow_t;

struct udx_flow_s {
    char addr[INET6_ADDRSTRLEN];
    uint16_t port;
    bool complete; // we have seen the remote id in this direction
    uint32_t id;

    uint32_t seq;
    uint32_t ack;
    uint32_t rwnd;

    int retransmits;

    udx_cirbuf_t outgoing;
    // udx_cirbuf_t incoming_out_of_order; // todo

    struct {
        uint32_t start;
        uint32_t end;
    } sacks[32];
    int nsacks;
};

// the tw flows are arbitrarily ordered by lexical
// ordering of the source address

struct udx_stream_s {
    udx_flow_t flow[2];

    udx_flow_t *fwd; // points to the flow that is sending data
    udx_flow_t *rev; // points to the flow acking data.
                     // these may flip whenever data is sent bidirectionally

    udx_stream_t *hash_next;
};

#define HASH_SIZE 1024
udx_stream_t *stream_table[HASH_SIZE];

bool
stream_equal (udx_stream_t *stream, char *saddr, uint16_t sport, char *daddr, uint16_t dport, uint32_t remote_id) {

    if (strcmp(saddr, daddr) < 0 || (strcmp(saddr, daddr) == 0 && sport < dport)) {
        if (strcmp(stream->flow[0].addr, saddr) == 0 && stream->flow[0].port == sport &&
            strcmp(stream->flow[1].addr, daddr) == 0 && stream->flow[1].port == dport) {
            if (stream->flow[1].complete) {
                return stream->flow[1].id == remote_id;
            } else {
                stream->flow[1].complete = true;
                stream->flow[1].id = remote_id;
                output_suffix("\t(identified stream: %s:%d.%d <-> %s:%d.%d)", stream->flow[0].addr, stream->flow[0].port, stream->flow[0].id, stream->flow[1].addr, stream->flow[1].port, stream->flow[1].id);
                return true;
            }
        }
    } else {
        if (strcmp(stream->flow[0].addr, daddr) == 0 && stream->flow[0].port == dport &&
            strcmp(stream->flow[1].addr, saddr) == 0 && stream->flow[1].port == sport) {
            if (stream->flow[0].complete) {
                return stream->flow[0].id == remote_id;
            } else {
                stream->flow[0].complete = true;
                stream->flow[0].id = remote_id;
                output_suffix("\t(identified stream: %s:%d.%d <-> %s:%d.%d)", stream->flow[0].addr, stream->flow[0].port, stream->flow[0].id, stream->flow[1].addr, stream->flow[1].port, stream->flow[1].id);
                return true;
            }
        }
    }
    return false;
}

udx_stream_t *
lookup (char *saddr, uint16_t sport, char *daddr, uint16_t dport, uint32_t id) {
    uint32_t key;

    if (sport < dport) {
        key = (dport * sport) % 1021;
    } else {
        key = (sport * dport) % 1021;
    }

    udx_stream_t **pstream = &stream_table[key];

    int depth = 0;

    for (;;) {
        udx_stream_t *stream = *pstream;
        if (stream == NULL) break;
        if (stream_equal(stream, saddr, sport, daddr, dport, id)) {
            return stream;
        } else {
            depth++;
            pstream = &stream->hash_next;
        }
    }

    // not found
    udx_stream_t *stream = calloc(1, sizeof(*stream));

    // impose an order on the flows so that can compare them
    if (strcmp(saddr, daddr) < 0 || (strcmp(saddr, daddr) == 0 && sport < dport)) {
        memcpy(stream->flow[0].addr, saddr, INET6_ADDRSTRLEN);
        stream->flow[0].port = sport;
        memcpy(stream->flow[1].addr, daddr, INET6_ADDRSTRLEN);
        stream->flow[1].port = dport;
        stream->flow[1].id = id;
        stream->flow[1].complete = true;
    } else {
        memcpy(stream->flow[0].addr, daddr, INET6_ADDRSTRLEN);
        stream->flow[0].port = dport;
        memcpy(stream->flow[1].addr, saddr, INET6_ADDRSTRLEN);
        stream->flow[1].port = sport;
        stream->flow[0].id = id;
        stream->flow[0].complete = true;
    }
    *pstream = stream;

    udx__cirbuf_init(&stream->flow[0].outgoing, 16);
    udx__cirbuf_init(&stream->flow[1].outgoing, 16);

    output_suffix("\t(new stream %s:%d -> %s:%d.%d)", saddr, sport, daddr, dport, id);

    return stream;
}

typedef struct dht_request_s dht_request_t;

struct dht_request_s {
    int tid;
    bool internal;
    int command;
};

// linear scan these, may want to hash by tid later though
dht_request_t pending[2048];
int npending;

dht_request_t *
find_request (int tid) {
    for (int i = 0; i < npending; i++) {
        if (pending[i].tid == tid) {
            return &pending[i];
        }
    }
    return NULL;
}

dht_request_t *
add_dht_request (int tid, bool internal, int command) {
    assert(npending < 2048);
    dht_request_t *req = &pending[npending++];
    req->tid = tid;
    req->internal = internal;
    req->command = command;

    return &pending[npending++];
}

// each parsing function passes a payload to the start of it's header
void
parse_ipv4 (uint8_t *payload, int len);
void
parse_ipv6 (uint8_t *payload, int len);
void
parse_udp (uint8_t *payload, int len);
void
parse_appl (uint8_t *payload, int len);
void
parse_udx (uint8_t *payload, int len);

int
main (int argc, char **argv) {

    opts.print_packet_bytes = false;
    for (int i = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == 'v') {
                opts.print_packet_bytes = true;
                continue;
            }
        }
    }
    // int fd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd == -1) {
        perror("socket");
        return 1;
    }

    int rcvbuf_size = 212992;

    int rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
    if (rc == -1) {
        perror("setsockopt");
        return 1;
    }

    uint8_t buf[2048];
    // struct iovec iov;
    // iov.iov_base = buf;
    // iov.iov_len = sizeof(buf);

    // union {
    //     struct cmsghdr align;
    //     uint8_t buf[2048];
    // } cmsg;

    // struct msghdr m;

    struct sockaddr_ll addr_ll;

    // m.msg_name = &addr_ll;
    // m.msg_namelen = sizeof(addr_ll);
    // m.msg_iov = &iov;
    // m.msg_iovlen = 1;
    // m.msg_control = &cmsg;
    // m.msg_controllen = sizeof(cmsg);

    while (1) {
        socklen_t addrlen;
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &addr_ll, &addrlen);

        // todo: select on our fd + STDIN to change modes
        // ssize_t n = recvmsg(fd, &m, 0);

        // prevent duplicate packets on loopback interface
        // assumes loopback is ifindex 1
        if (addr_ll.sll_ifindex == 1 && addr_ll.sll_pkttype == PACKET_OUTGOING) continue;

        line = line_buf;
        linelen = 0;
        prefix = prefix_buf;
        prefixlen = 0;
        suffix = suffix_buf;
        suffixlen = 0;

        if (n == -1) {
            perror("recvfrom");
            return 1;
        }
        eth = (struct ethhdr *) buf;

        int ethhdrlen = sizeof(struct ethhdr);

        if (ntohs(eth->h_proto) == 0x0800) {
            parse_ipv4(buf + ethhdrlen, n - ethhdrlen);
        } else if (ntohs(eth->h_proto) == 0x86DD) {
            parse_ipv6(buf + ethhdrlen, n - ethhdrlen);
        } else {
            // printf("non-ip %x\n", ntohs(eth->h_proto));
            // ignore packet:
            continue;
        }
    }
}
void
parse_ipv4 (uint8_t *payload, int len) {
    ip = (struct iphdr *) payload;
    ip6 = NULL;

    int version = ip->version;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    assert(version == 4);
    struct sockaddr_in *saddr = (struct sockaddr_in *) &source;
    struct sockaddr_in *daddr = (struct sockaddr_in *) &dest;
    saddr->sin_addr.s_addr = ip->saddr;
    daddr->sin_addr.s_addr = ip->daddr;

    inet_ntop(AF_INET, &saddr->sin_addr, source_name, sizeof(source_name));
    inet_ntop(AF_INET, &daddr->sin_addr, dest_name, sizeof(dest_name));

    int iphdrlen = ip->ihl * 4;
    int protocol = ip->protocol;

    if (protocol != 0x11 /* UDP */) {
        return;
    }
    int totallen = ntohs(ip->tot_len);
    int flags_and_frag_offset = ntohs(ip->frag_off);

    int flags = (flags_and_frag_offset >> 13) & 0x7;

    bool fragmented = flags & 0x1;
    int frag_offset = flags_and_frag_offset & 0x1fff;

    if (fragmented) {
        printf("fragment! ");
    }

    if (totallen != len) {
        printf("%s->%s len=%d fragment discarded\n", source_name, dest_name, len);
        return;
    }

    payload += iphdrlen;
    len -= iphdrlen;

    parse_udp(payload, len);
}

void
parse_ipv6 (uint8_t *payload, int len) {
    int iphdrlen = sizeof(struct ip6_hdr);
    ip = NULL;
    ip6 = (struct ip6_hdr *) payload;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) &source;
    struct sockaddr_in6 *daddr = (struct sockaddr_in6 *) &dest;
    saddr->sin6_addr = ip6->ip6_src;
    daddr->sin6_addr = ip6->ip6_dst;

    inet_ntop(AF_INET6, &saddr->sin6_addr, source_name, sizeof(source_name));
    inet_ntop(AF_INET6, &daddr->sin6_addr, dest_name, sizeof(dest_name));

    payload += sizeof(struct ip6_hdr);
    len -= iphdrlen;

    parse_udp(payload, len);
}

void
parse_udp (uint8_t *payload, int len) {
    udp = (struct udphdr *) payload;
    int header_len = sizeof(struct udphdr);

    payload += header_len;
    len -= header_len;

    parse_appl(payload, len);
}

typedef enum {
    DHT_OK,
    DHT_ABORTED,
    DHT_VERSION_MISMATCH,
    DHT_TRY_LATER,
    DHT_SEQ_REUSED = 16,
    DHT_SEQ_TOO_LOW,
} dht_rpc_error_t;

typedef enum {
    DHT_CMD_PING,
    DHT_CMD_PING_NAT,
    DHT_CMD_FIND_NODE,
    DHT_CMD_DOWN_HINT
} dht_rpc_internal_command_type_t;

typedef enum {
    HYPERDHT_CMD_PEER_HANDSHAKE,
    HYPERDHT_CMD_PEER_HOLEPUNCH,
    HYPERDHT_CMD_FIND_PEER,
    HYPERDHT_CMD_LOOKUP,
    HYPERDHT_CMD_ANNOUNCE,
    HYPERDHT_CMD_UNANNOUNCE,
    HYPERDHT_CMD_MUTABLE_PUT,
    HYPERDHT_CMD_MUTABLE_GET,
    HYPERDHT_CMD_IMMUTABLE_PUT,
    HYPERDHT_CMD_IMMUTABLE_GET
} dht_hyperdht_command_type_t;

#define DHT_FLAG_ID       0b00001
#define DHT_FLAG_TOKEN    0b00010
#define DHT_FLAG_INTERNAL 0b00100
#define DHT_FLAG_TARGET   0b01000 // request only
#define DHT_FLAG_ERROR    0b01000 // response only
#define DHT_FLAG_VALUE    0b10000

char *hyperdht_command[] = {
    "PEER_HANDSHAKE",
    "PEER_HOLEPUNCH",
    "FIND_PEER",
    "LOOKUP",
    "ANNOUNCE",
    "UNANNOUNCE",
    "MUTABLE_PUT",
    "MUTABLE_GET",
    "IMMUTABLE_PUT",
    "IMMUTABLE_GET"
};

char *internal_dht_command[] = {
    "PING",
    "PING_NAT",
    "FIND_NODE",
    "DOWN_HINT",
};

typedef struct {
    uint64_t value;
    int nbytes;
} compact_uint_t;

uint64_t
decode_compact_integer (uint8_t **payload, int *len) {
    uint8_t *p = *payload;
    uint64_t value = *p;
    int nbytes = 0;

    if (value > 0xfc) {
        value = 0;
        if (value == 0xfd) nbytes = 2;
        if (value == 0xfe) nbytes = 4;
        if (value == 0xff) nbytes = 8;

        for (int i = 0; i < nbytes; i++) {
            value = (value << 8) + *p++;
        }
    }

    *payload = p;
    *len -= nbytes + 1;

    return value;
}

void
decode_noise (uint8_t **payload, int *plen) {
    assert(*plen >= 4);

    int len = *plen;

    uint8_t *p = *payload;

    int version = *p++;
    int flags = *p++;
    int error = *p++;
    int firewall = *p++;
    len += 4;

    if (flags & 0x01) {
        uint64_t id = decode_compact_integer(&p, &len);
        output("id=%" PRIu64);
    }
    if (flags & 0x02) {
        uint64_t value = decode_compact_integer(&p, &len);
        p += 6 * value;
        output("IPv4 ");
    }
    if (flags & 0x04) {
        uint64_t value = decode_compact_integer(&p, &len);
        p += 18 * value;
        output("IPv6 ");
    }
    if (flags & 0x08) {
        int version = *p++;
        int features = *p++;
        uint32_t id = decode_compact_integer(&p, &len);
        uint32_t seq = decode_compact_integer(&p, &len);
        output("version=%d features=%d id=%u, seq=%u ", version, features, id, seq);
    }
    if (flags & 0x16) {
        uint64_t secret_stream_state = decode_compact_integer(&p, &len);
        output("Secret Stream State=% " PRIu64, secret_stream_state);
    }
    if (flags & 0x32) {
        // relaythrough
        int version = *p++;
        int flags = *p++;
        uint8_t *public_key_32 = p;
        p += 32;
        uint8_t *token_32 = p;
        p += 32;
    }
    *plen -= (p - *payload);
    *payload = p;
    return;
}

void
print_bytes (uint8_t *p, int len) {
    for (int i = 0; i < len; i++) {
        output("%02x", *p++);
    }
}

void
parse_dht_rpc (uint8_t *payload, int len) {
    bool request = !(payload[0] & 0x10);

    int version = payload[0] & 0x0f;
    int flags = payload[1];

    int tid = payload[2] + (payload[3] << 8);

    output("dht-rpc %15s:%d -> %15s:%d tid=%4x %s", source_name, ntohs(udp->source), dest_name, ntohs(udp->dest), tid, request ? "REQ  " : "RESP ");

    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &payload[4], addr, sizeof(addr));

    // output("to: addr=");
    // for (int i = 4; i < 8; i++) {
    //     output("%02x", payload[i]);
    // }

    int port = payload[8] + (payload[9] << 8);
    output("%15s:%d ", addr, port);

    uint8_t *p = &payload[10];
    len -= 10;

    if (flags & DHT_FLAG_ID) {
        output("id=");
        print_bytes(p, 32);
        p += 32;
        len -= 32;
        output(" ");
    }

    if (flags & DHT_FLAG_TOKEN) {
        output("token=");
        print_bytes(p, 32);
        p += 32;
        len -= 32;
        output(" ");
    }

    if (request) {

        uint64_t command = decode_compact_integer(&p, &len);
        bool internal = flags & DHT_FLAG_INTERNAL;

        if (command > 8 || (internal && command > 4)) {
            printf("bad command? command=%" PRIu64 "\n", command);
            return;
        }

        add_dht_request(tid, internal, command);
        output("%s", internal ? internal_dht_command[command] : hyperdht_command[command]);

        if (internal) {
            ;
        } else {
            if (command == HYPERDHT_CMD_PEER_HANDSHAKE) {
                int flags = *p++;
                int mode = *p++;
                len -= 2;
                printf("flags=%d mode=%d\n", flags, mode);

                if (mode > 4) {
                    __builtin_trap();
                }

                char *modes[] = {
                    "FROM_CLIENT",
                    "FROM_SERVER",
                    "FROM_RELAY",
                    "FROM_SECOND_RELAY",
                    "REPLY",
                };

                output("%s %s mode=%d", flags & 0x01 ? "PEER ADDRESS" : "", flags & 0x02 ? "+Relay Address" : "", modes[mode]);
                // decode_noise(&p, &len);

                // if (flags & 0x01 /* peer address */) {
                //     uint32_t address = 0;
                //     uint16_t port = 0;
                //     for (int i = 0; i < 4; i++) {
                //         address = (address << 8) + *p++;
                //     }
                //     port = *p++;
                //     port = (port << 8) + *p++;
                // }
                // if (flags & 0x02 /* relay address */) {

                //     uint32_t address = 0;
                //     uint16_t port = 0;
                //     for (int i = 0; i < 4; i++) {
                //         address = (address << 8) + *p++;
                //     }
                //     port = *p++;
                //     port = (port << 8) + *p++;
                // }
            } else if (command == HYPERDHT_CMD_PEER_HOLEPUNCH) {
                // holepunchInfo goes to noisePayload
                // exports.holepunch is the request?
                int flags = *p++;
                int mode = *p++;
                len -= 2;
                uint32_t id = decode_compact_integer(&p, &len);
                output("flags=%d mode=%d id=%u", flags, mode, id);
                int arraylen = decode_compact_integer(&p, &len);
            }
        }
    } else {
        // response

        dht_request_t *req = find_request(tid);
        int req_index = req - pending;

        output("%s", req->internal ? internal_dht_command[req->command] : hyperdht_command[req->command]);
        npending--;
        if (npending > 0) {
            pending[req_index] = pending[npending];
        }

        // reply (flag is 0x4.. not sure i that's necessarily internal or what
        if (flags & DHT_FLAG_INTERNAL) {
            uint64_t count = *p++;

            if (count > 0xfc) {
                count = 0;
                int nbytes = 0;
                if (count == 0xfd) nbytes = 2;
                if (count == 0xfe) nbytes = 4;
                if (count == 0xff) nbytes = 8;

                for (int i = 0; i < nbytes; i++) {
                    count = (count << 8) + *p++;
                }
            }

            for (int i = 0; i < count; i++) {
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, p, addr, sizeof(addr));
                p += 4;
                port = p[0] + (p[1] << 8);
                p += 2;
            }
        }

        if (flags & DHT_FLAG_ERROR) {
            uint64_t error = *p++;

            if (error > 0xfc) {
                error = 0;
                int nbytes = 0;
                if (error == 0xfd) nbytes = 2;
                if (error == 0xfe) nbytes = 4;
                if (error == 0xff) nbytes = 8;

                for (int i = 0; i < nbytes; i++) {
                    error = (error << 8) + *p++;
                }
            }

            char *error_string = NULL;

            switch (error) {
            case DHT_OK:
                error_string = "DHT_OK";
                break;
            case DHT_ABORTED:
                error_string = "DHT_ABORTED";
                break;
            case DHT_VERSION_MISMATCH:
                error_string = "DHT_VERSION_MISMATCH";
                break;
            case DHT_TRY_LATER:
                error_string = "DHT_TRY_LATER";
                break;
            case DHT_SEQ_REUSED:
                error_string = "DHT_SEQ_REUSED";
                break;
            case DHT_SEQ_TOO_LOW:
                error_string = "DHT_SEQ_TOO_LOW";
                break;
            default:
                __builtin_trap();
            }

            output("%s", error_string);
        }
    }

    len -= (p - payload);
    payload = p;

    if (flags & DHT_FLAG_VALUE) {
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0) {
                output("\n\t");
            }
            output("%02x ", payload[i]);
        }
    }

    final_output();
}
void
parse_appl (uint8_t *payload, int len) {
    if (len >= 20 && payload[0] == 0xff && payload[1] == 1) {
        parse_udx(payload, len);
    } else if (len > 1 && (payload[0] == 3 || payload[0] == 19)) {
        parse_dht_rpc(payload, len);
    }
    // non-dht, non-udx packet,drop

    return;
}

#define UDX_HEADER_DATA    0b00001
#define UDX_HEADER_END     0b00010
#define UDX_HEADER_SACK    0b00100
#define UDX_HEADER_MESSAGE 0b01000
#define UDX_HEADER_DESTROY 0b10000

void
parse_udx (uint8_t *payload, int len) {
    uint8_t *p = payload;

    int magic = *p++;
    int udx_version = *p++;
    int flags = *p++;
    int data_offset = *p++;

    uint32_t *i = (uint32_t *) p;

    uint32_t id = *i++;
    uint32_t rwnd = *i++;
    uint32_t seq = *i++;
    uint32_t ack = *i++;

    payload = (uint8_t *) i;
    len -= 20;

    output("udx %15s:%d -> %15s:%d %8x seq=%10u ack=%10u", source_name, ntohs(udp->source), dest_name, ntohs(udp->dest), id, seq, ack);

    int _flags = flags;

    bool is_ack = (flags == 0);
    output(" ");
    if (is_ack) {
        output("ACK");
    } else {
        if (_flags & UDX_HEADER_DATA) {
            output("DATA");
            _flags &= ~UDX_HEADER_DATA;
            if (_flags) {
                output("|");
            }
        }
        if (_flags & UDX_HEADER_END) {
            output("END");
            _flags &= ~UDX_HEADER_END;
            if (_flags) {
                output("|");
            }
        }
        if (_flags & UDX_HEADER_SACK) {
            output("SACK");
            _flags &= ~UDX_HEADER_SACK;
            if (_flags) {
                output("|");
            }
        }
        if (_flags & UDX_HEADER_MESSAGE) {
            // message is probably mutually exclusive in practice with the other _flags, but it's ok
            output("MESSAGE");
            _flags &= ~UDX_HEADER_MESSAGE;
            if (_flags) {
                output("|");
            }
        }
        if (_flags & UDX_HEADER_DESTROY) {
            output("DESTROY");
            _flags &= ~UDX_HEADER_DESTROY;
            if (_flags) {
                output_suffix("(weird flag set, flags=%x)", flags);
            }
        }
    }

    bool data = flags & UDX_HEADER_DATA;
    bool end = flags & UDX_HEADER_END;
    bool sack = flags & UDX_HEADER_SACK;
    bool message = flags & UDX_HEADER_MESSAGE;
    bool destroy = flags & UDX_HEADER_DESTROY;

    if (sack) {
        assert((data_offset % 8) == 0);
        for (int j = 0; j < data_offset; j += 8) {
            output("%u:%u", i[0], i[1]);
            i += 2;
        }
    }

    payload += data_offset;
    len -= data_offset;

    udx_stream_t *stream = lookup(source_name, ntohs(udp->source), dest_name, ntohs(udp->dest), id);
    udx_flow_t *flow = stream->flow[0].id == id ? &stream->flow[0] : &stream->flow[1];

    if (data) {
        if (stream->flow[0].id == id) {
            stream->fwd = &stream->flow[0];
            stream->rev = &stream->flow[1];
        } else {
            stream->fwd = &stream->flow[1];
            stream->rev = &stream->flow[0];
        }
    }

    if (data && seq != stream->fwd->seq + 1) {
        // should be seq_le, account for sequence wrap
        if (seq < stream->fwd->seq + 1) {
            stream->fwd->retransmits++;
            output_suffix("\t(retransmit)");
        }
        if (seq > stream->fwd->seq + 1) {
            output_suffix("\t OOO sequece. maybe dropped packets: %d", seq - stream->fwd->seq);
        }
    }

    flow->seq = seq;
    flow->ack = ack;
    flow->rwnd = rwnd;

    if (stream->fwd && stream->rev) {
        int inflight = stream->fwd->seq - (stream->rev->ack - 1);
        // output(" inflight=%d", inflight);
    }

    if (data && opts.print_packet_bytes) {
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0) {
                output("\n\t");
            }
            output("%02x ", payload[i]);
        }
    }

    final_output();
}
