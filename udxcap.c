
#include <assert.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "all.h"

// todo:
// 1.measure rtt. trickier than you might expect,
// with tcp it's the time for sending SYN, receiving SYN+ACK, and then sending
// ACK simply measuring from DATA to ACK is not enough, if we're on capturing
// host that's receiving that only measures the time spent processing technique:
// measure the time between the first DATA packet and the 11th data packet

#define FILTER_SZ 8192

char filter[FILTER_SZ];
int filter_sz;

struct sockaddr_storage source;
struct sockaddr_storage dest;

char source_name[INET6_ADDRSTRLEN];
char dest_name[INET6_ADDRSTRLEN];

struct timeval packet_time;

eth_hdr_t *eth;
ip4_hdr_t *ip4;
ip6_hdr_t *ip6;
udp_hdr_t *udp;

// output is grouped into triplets of lines: a prefix, the line itself, and a
// suffix. output_prefix(), output(), and output_suffix() are used to write to
// these buffers.
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
    char *interface;         // e.g. 'eth0', NULL if not provided.
    char *read_file;         // '-r' option, NULL if not provided.
    bool print_packet_bytes; // '-v' option
    char *filter;            // NULL if not provided, pointers to an argv if -f is used or to the 'filter' global if a filter is constructed from position arguments
    bool generate_graphs;    // '-g' option
} opts;

void
output (char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    linelen += vsnprintf(line, sizeof(line_buf) - linelen, fmt, ap);
    assert(linelen >= 0);
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

    // data for a 1-second slice of time
    uint32_t next_seq; // expected sequence
    uint32_t seq;
    uint32_t ack;
    uint32_t rwnd;

    struct timeval start_time; // tv_sec, tv_usec
    struct timeval time;       // time of last packet

    FILE *graph_file;
    // when the clock second-hand rolls over write
    // these data into the graph_file
    uint64_t packets_this_second;
    uint64_t bytes_this_second;

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

    if (strcmp(saddr, daddr) < 0 ||
        (strcmp(saddr, daddr) == 0 && sport < dport)) {
        if (strcmp(stream->flow[0].addr, saddr) == 0 &&
            stream->flow[0].port == sport &&
            strcmp(stream->flow[1].addr, daddr) == 0 &&
            stream->flow[1].port == dport) {
            if (stream->flow[1].complete) {
                return stream->flow[1].id == remote_id;
            } else {
                stream->flow[1].complete = true;
                stream->flow[1].id = remote_id;
                output_suffix("\t(identified stream: %s:%d.%10u <-> %s:%d.%10u)", stream->flow[0].addr, stream->flow[0].port, stream->flow[0].id, stream->flow[1].addr, stream->flow[1].port, stream->flow[1].id);
                return true;
            }
        }
    } else {
        if (strcmp(stream->flow[0].addr, daddr) == 0 &&
            stream->flow[0].port == dport &&
            strcmp(stream->flow[1].addr, saddr) == 0 &&
            stream->flow[1].port == sport) {
            if (stream->flow[0].complete) {
                return stream->flow[0].id == remote_id;
            } else {
                stream->flow[0].complete = true;
                stream->flow[0].id = remote_id;
                output_suffix("\t(identified stream: %s:%d.%10u <-> %s:%d.%10u)", stream->flow[0].addr, stream->flow[0].port, stream->flow[0].id, stream->flow[1].addr, stream->flow[1].port, stream->flow[1].id);
                return true;
            }
        }
    }
    return false;
}

// source & destination ports are passed as uint32_t
// so that they are not promoted to signed int by the hash
// function. important!
udx_stream_t *
lookup (char *saddr, uint32_t sport, char *daddr, uint32_t dport, uint32_t id) {
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
        if (stream == NULL)
            break;
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
    if (strcmp(saddr, daddr) < 0 ||
        (strcmp(saddr, daddr) == 0 && sport < dport)) {
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

    output_suffix("\t(new stream %s:%d -> %s:%d.%10u)", saddr, sport, daddr, dport, id);

    return stream;
}

typedef struct dht_request_s dht_request_t;

struct dht_request_s {
    int tid;
    bool internal;
    int command;

    dht_request_t *hash_next;
};

dht_request_t *pending[HASH_SIZE];

dht_request_t **
find_dht_request (int tid) {
    dht_request_t **p = &pending[tid & (HASH_SIZE - 1)];

    while (*p != NULL) {
        if ((*p)->tid == tid) {
            return p;
        }
        p = &(*p)->hash_next;
    }

    return p;
}
dht_request_t *
find_or_create_dht_request (int tid) {
    dht_request_t **p = find_dht_request(tid);

    if (*p == NULL) {
        *p = calloc(1, sizeof(dht_request_t));
        (*p)->tid = tid;
    }

    return *p;
}

// each parsing function passes a payload to the start of it's header
void
parse_ipv4 (const uint8_t *payload, int len);
void
parse_ipv6 (const uint8_t *payload, int len);
void
parse_udp (const uint8_t *payload, int len);
void
parse_appl (const uint8_t *payload, int len);
void
parse_udx (const uint8_t *payload, int len);

int dlt;
int packet_byte_size;

void
on_packet (u_char *ctx, const struct pcap_pkthdr *header, const u_char *payload) {

    line = line_buf;
    linelen = 0;
    prefix = prefix_buf;
    prefixlen = 0;
    suffix = suffix_buf;
    suffixlen = 0;

    packet_byte_size = header->len;

    if (header->caplen < header->len) {
        printf("dropping incomplete packet caplen=%d len=%d\n", header->caplen, header->len);
        return;
    }
    int proto;
    int llhdr_size;
    if (dlt == DLT_EN10MB) {

        eth = (eth_hdr_t *) payload;

        proto = htons(eth->ether_type);

        llhdr_size = sizeof(eth_hdr_t);

    } else if (dlt == DLT_LINUX_SLL2) {
        sll2_hdr_t *sll = (sll2_hdr_t *) payload;

        int arphrd_type = ntohs(sll->arphrd_type);

        proto = ntohs(sll->protocol_type);
        llhdr_size = sizeof(sll2_hdr_t);
        printf("proto=%d apphdr_type=%d\n", proto, arphrd_type);
    } else if (dlt == DLT_LINUX_SLL) {
        sll_hdr_t *sll = (sll_hdr_t *) payload;

        int arphrd_type = ntohs(sll->arphrd_type);

        proto = ntohs(sll->protocol_type);
        llhdr_size = sizeof(sll_hdr_t);
        printf("proto=%d apphdr_type=%d\n", proto, arphrd_type);
    } else {
        assert(0);
    }

    packet_time = header->ts;

    if (proto == 0x800) {
        parse_ipv4(payload + llhdr_size, header->len - llhdr_size);
    } else if (proto == 0x86dd) {
        parse_ipv6(payload + llhdr_size, header->len - llhdr_size);
    } else {
        return;
    }

    return;
}

/*
void
parse_filter (int arg1, int argc, char **argv) {
    printf("parse filter, %d %d arg=%s\n", arg1, argc, argv[arg1]);
    char *p = filter;
    int remainder = FILTER_SZ;

    for (int i = arg1; i < argc; i++) {
        char *arg = argv[i];
        int n = snprintf(p, remainder, "%s ", arg);
        remainder -= n;
        p += n;
    }

    filter_sz = p - filter;
    filter[filter_sz] = '\0';

    printf("filter=%.*s\n", filter_sz, filter);
    opts.filter = filter;
}
*/

int
main (int argc, char **argv) {
    int current_option = 0; // option being parsed

    opts.filter = "udp"; // default - at least filter out non-udp traffic

    opts.print_packet_bytes = false;
    for (int i = 1; i < argc; i++) {

        char *arg = argv[i];
        printf("arg %d %s\n", i, argv[i]);

        switch (current_option) {
        case 0:
            break;
        case 'i':
            opts.interface = arg;
            current_option = 0;
            continue;
        case 'r':
            opts.read_file = arg;
            current_option = 0;
            continue;
        case 'f':
            opts.filter = arg;
            current_option = 0;
            continue;
        default:
            fprintf(stderr, "error: unknown option -%c\n", current_option);
            return 1;
        }
        if (arg[0] == '-') {
            if (arg[1] == 'v') {
                opts.print_packet_bytes = true;
                continue;
            }
            if (arg[1] == 'i') {
                current_option = 'i';
                continue;
            }
            if (arg[1] == 'r') {
                current_option = 'r';
                continue;
            }
            if (arg[1] == 'f') {
                current_option = 'f';
                continue;
            }
            if (arg[1] == 'g') {
                opts.generate_graphs = true;
                continue;
            }
        }
        fprintf(stderr, "unknown option '%s'\n", arg);
        return 1;
    }

    int rc;

    char errbuf[PCAP_ERRBUF_SIZE];
    rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (rc != 0) {
        fprintf(stderr, "pcap_init: %s\n", errbuf);
        return 1;
    }
    pcap_t *handle = NULL;

    if (opts.read_file) {
        handle = pcap_open_offline(opts.read_file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
            return 1;
        }
    } else if (opts.interface) {
        // handle = pcap_create(opts.interface, errbuf);
        handle = pcap_open_live(opts.interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
            return 1;
        }
    } else {
        pcap_if_t *alldevs = NULL;
        rc = pcap_findalldevs(&alldevs, errbuf);

        if (rc != 0 || alldevs == NULL /* no error but no devices */) {
            fprintf(stderr, "couldn't find default device. err=%s\n", errbuf);
            return 1;
        }

        pcap_if_t *dev = alldevs;

        handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev->name, errbuf);
            pcap_freealldevs(alldevs);
            return 1;
        }
        pcap_freealldevs(alldevs);
    }

    dlt = pcap_datalink(handle);

    if (dlt != DLT_EN10MB && dlt != DLT_LINUX_SLL2 && dlt != DLT_LINUX_SLL) {
        fprintf(stderr, "selected device doesn't provide ethernet headers, datalink type=%d", pcap_datalink(handle));
        return 1;
    }

    if (opts.filter) {
        struct bpf_program fp;
        rc = pcap_compile(handle, &fp, opts.filter, 0, PCAP_NETMASK_UNKNOWN);
        if (rc != 0) {
            fprintf(stderr, "couldn't compile filter %s: %s\n", opts.filter, pcap_geterr(handle));
            return 1;
        }
        rc = pcap_setfilter(handle, &fp);

        if (rc != 0) {
            fprintf(stderr, "couldn't install filter %s: %s\n", opts.filter, pcap_geterr(handle));
            return 1;
        }
    }

    rc = pcap_loop(handle, -1, on_packet, NULL);
    if (rc != 0) {
        fprintf(stderr, "pcap loop\n");
        return 1;
    }

    if (opts.generate_graphs) {
        // just iterate the hash table
        for (int i = 0; i < HASH_SIZE; i++) {
            udx_stream_t *s = stream_table[i];
            while (s != NULL) {
                if (s->flow[0].graph_file)
                    fclose(s->flow[0].graph_file);
                if (s->flow[1].graph_file)
                    fclose(s->flow[1].graph_file);
                s = s->hash_next;
            }
        }
    }

    return 0;
}

void
parse_ipv4 (const uint8_t *payload, int len) {
    ip4 = (ip4_hdr_t *) payload;
    ip6 = NULL;

    int version = ip4->v_and_hl >> 4;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    assert(version == 4);
    struct sockaddr_in *saddr = (struct sockaddr_in *) &source;
    struct sockaddr_in *daddr = (struct sockaddr_in *) &dest;
    saddr->sin_addr.s_addr = ip4->saddr;
    daddr->sin_addr.s_addr = ip4->daddr;

    inet_ntop(AF_INET, &saddr->sin_addr, source_name, sizeof(source_name));
    inet_ntop(AF_INET, &daddr->sin_addr, dest_name, sizeof(dest_name));

    int ip_header_len_bytes = (ip4->v_and_hl & 0xf) * 4; //
    int protocol = ip4->protocol;

    if (protocol != 0x11 /* UDP */) {
        return;
    }
    int ipv4_len = ntohs(ip4->tot_len);
    int flags_and_frag_offset = ntohs(ip4->frag_off);

    int flags = (flags_and_frag_offset >> 13) & 0x7;

    bool fragmented = flags & 0x1;
    int frag_offset = flags_and_frag_offset & 0x1fff;

    if (fragmented) {
        printf("fragment! ");
    }

    parse_udp(payload + ip_header_len_bytes, ipv4_len - ip_header_len_bytes);
}

void
parse_ipv6 (const uint8_t *payload, int len) {
    ip4 = NULL;
    ip6 = (ip6_hdr_t *) payload;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) &source;
    struct sockaddr_in6 *daddr = (struct sockaddr_in6 *) &dest;

    memcpy(&saddr->sin6_addr, &ip6->src, 16);
    memcpy(&daddr->sin6_addr, &ip6->dst, 16);

    inet_ntop(AF_INET6, &saddr->sin6_addr, source_name, sizeof(source_name));
    inet_ntop(AF_INET6, &daddr->sin6_addr, dest_name, sizeof(dest_name));

    int payload_len = ntohs(ip6->payload_len);
    int next_header = ip6->next_header;

    if (next_header != 17) {
        // only interested in UP packets without extensions
        return;
    }
    parse_udp(payload + sizeof(ip6_hdr_t), len - payload_len);
}

void
parse_udp (const uint8_t *payload, int len) {
    udp = (udp_hdr_t *) payload;

    parse_appl(payload + sizeof(udp_hdr_t), len - sizeof(udp_hdr_t));
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

char *hyperdht_command[] = {"PEER_HANDSHAKE", "PEER_HOLEPUNCH", "FIND_PEER", "LOOKUP", "ANNOUNCE", "UNANNOUNCE", "MUTABLE_PUT", "MUTABLE_GET", "IMMUTABLE_PUT", "IMMUTABLE_GET"};

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
decode_compact_integer (uint8_t **payload) {
    uint8_t *p = *payload;
    uint64_t value = *p++;
    int nbytes = 0;

    if (value > 0xfc) {
        value = 0;
        if (value == 0xfd)
            nbytes = 2;
        if (value == 0xfe)
            nbytes = 4;
        if (value == 0xff)
            nbytes = 8;

        for (int i = 0; i < nbytes; i++) {
            value = (value << 8) + *p++;
        }
    }

    *payload = p;

    return value;
}

void
decode_noise (uint8_t **payload, int len) {
    assert(len >= 4);

    uint8_t *p = *payload;

    int version = *p++;
    int flags = *p++;
    int error = *p++;
    int firewall = *p++;

    if (flags & 0x01) {
        uint64_t id = decode_compact_integer(&p);
        output("id=%" PRIu64, id);
    }
    if (flags & 0x02) {
        uint64_t value = decode_compact_integer(&p);
        p += 6 * value;
        output("IPv4 ");
    }
    if (flags & 0x04) {
        uint64_t value = decode_compact_integer(&p);
        p += 18 * value;
        output("IPv6 ");
    }
    if (flags & 0x08) {
        int version = *p++;
        int features = *p++;
        uint32_t id = decode_compact_integer(&p);
        uint32_t seq = decode_compact_integer(&p);
        output("version=%d features=%d id=%u, seq=%u ", version, features, id, seq);
    }
    if (flags & 0x16) {
        uint64_t secret_stream_state = decode_compact_integer(&p);
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
parse_dht_rpc (const uint8_t *payload, int len) {

    const uint8_t *p_init = payload;

    output("%ld.%06ld ", packet_time.tv_sec, packet_time.tv_usec);

    bool request = !(payload[0] & 0x10);

    int version = payload[0] & 0x0f;
    int flags = payload[1];

    int tid = payload[2] + (payload[3] << 8);

    output("%15s:%d -> %15s:%d DHT-RPC tid=%5d %s", source_name, ntohs(udp->sport), dest_name, ntohs(udp->dport), tid, request ? "REQ  " : "RESP ");

    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &payload[4], addr, sizeof(addr));

    // output("to: addr=");
    // for (int i = 4; i < 8; i++) {
    //     output("%02x", payload[i]);
    // }

    int port = payload[8] + (payload[9] << 8);
    output("%15s:%d ", addr, port);

    uint8_t *p = (uint8_t *) &payload[10];

    if (flags & DHT_FLAG_ID) {
        output("id=");
        print_bytes(p, 32);
        p += 32;
        output(" ");
    }

    if (flags & DHT_FLAG_TOKEN) {
        output("token=");
        print_bytes(p, 32);
        p += 32;
        output(" ");
    }

    if (request) {
        if (flags & DHT_FLAG_TARGET) {
            output("target=");
            print_bytes(p, 32);
            p += 32;
            output(" ");
        }

        uint64_t command = decode_compact_integer(&p);
        bool internal = flags & DHT_FLAG_INTERNAL;

        if (command > 8 || (internal && command > 4)) {
            printf("bad command? command=%" PRIu64 "\n", command);
            return;
        }

        dht_request_t *req = find_or_create_dht_request(tid);
        req->internal = internal;
        req->command = command;

        output("%s", internal ? internal_dht_command[command] : hyperdht_command[command]);

        if (internal) {
            ;
        } else {
            if (command == HYPERDHT_CMD_PEER_HANDSHAKE) {
                int flags = *p++;
                int mode = *p++;
                printf("flags=%d mode=%d\n", flags, mode);

                char *mode_str = "unknown";

                if (mode <= 4) {

                    char *modes[] = {
                        "FROM_CLIENT",
                        "FROM_SERVER",
                        "FROM_RELAY",
                        "FROM_SECOND_RELAY",
                        "REPLY",
                    };

                    mode_str = modes[mode];
                }

                output("%s %s mode=%s (%d)", flags & 0x01 ? " +peer address" : "", flags & 0x02 ? "+Relay Address" : "", mode_str, mode);
                // decode_noise(&p);

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
                uint32_t id = decode_compact_integer(&p);
                output("flags=%d mode=%d id=%u", flags, mode, id);
                int arraylen = decode_compact_integer(&p);
            }
        }
    } else {
        // response

        dht_request_t **preq = find_dht_request(tid);

        if (*preq != NULL) {
            output("%s", (*preq)->internal ? internal_dht_command[(*preq)->command] : hyperdht_command[(*preq)->command]);
            *preq = (*preq)->hash_next;
            free(*preq);
        }

        // reply (flag is 0x4.. not sure i that's necessarily internal or what
        if (flags & DHT_FLAG_INTERNAL) {
            uint64_t count = *p++;

            if (count > 0xfc) {
                count = 0;
                int nbytes = 0;
                if (count == 0xfd)
                    nbytes = 2;
                if (count == 0xfe)
                    nbytes = 4;
                if (count == 0xff)
                    nbytes = 8;

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
                if (error == 0xfd)
                    nbytes = 2;
                if (error == 0xfe)
                    nbytes = 4;
                if (error == 0xff)
                    nbytes = 8;

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

    if (flags & DHT_FLAG_VALUE) {
        int i = 0;
        while (p < p_init + len) {
            if (i % 16 == 0) {
                output("\n\t");
            }
            output("%02x ", *p++);
            i++;
        }
    }

    final_output();
}
void
parse_appl (const uint8_t *payload, int len) {
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
parse_udx (const uint8_t *payload, int len) {

    output("%ld.%06ld ", packet_time.tv_sec, packet_time.tv_usec);

    uint8_t *p = (uint8_t *) payload;

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

    output("%15s:%d -> %15s:%d UDX id=%10u seq=%u ack=%u", source_name, ntohs(udp->sport), dest_name, ntohs(udp->dport), id, seq, ack);

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
            // message is probably mutually exclusive in practice with the other
            // _flags, but it's ok
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

    udx_stream_t *stream =
        lookup(source_name, ntohs(udp->sport), dest_name, ntohs(udp->dport), id);
    udx_flow_t *flow =
        stream->flow[0].id == id ? &stream->flow[0] : &stream->flow[1];

    if (data) {
        if (stream->flow[0].id == id) {
            stream->fwd = &stream->flow[0];
            stream->rev = &stream->flow[1];
        } else {
            stream->fwd = &stream->flow[1];
            stream->rev = &stream->flow[0];
        }
    }

    if (flow->start_time.tv_sec == 0) {
        flow->start_time = packet_time;
        flow->time = packet_time;
    }

    if (opts.generate_graphs) {
        if (flow->graph_file == NULL) {
            char filename[120];
            snprintf(filename, 120, "%s:%d_%s:%d_%u.dat", source_name, ntohs(udp->sport), dest_name, ntohs(udp->dport), id);
            flow->graph_file = fopen(filename, "w+");
        }
        if (flow->graph_file && flow->time.tv_sec < packet_time.tv_sec) {
            fprintf(flow->graph_file, "%ld %ld %ld\n", flow->time.tv_sec - flow->start_time.tv_sec, flow->packets_this_second, flow->bytes_this_second);
            if (!opts.read_file) {
                // if user is live, flush as we go since they'll probably end with SIGINT
                fflush(flow->graph_file);
            }
            flow->packets_this_second = 0;
            flow->bytes_this_second = 0;
        }
    }

    flow->time = packet_time;
    flow->packets_this_second++;
    flow->bytes_this_second += packet_byte_size;

    if (data && stream->fwd->next_seq && seq != stream->fwd->next_seq) {
        // should be seq_le, account for sequence wrap
        if (seq < stream->fwd->next_seq) {
            stream->fwd->retransmits++;
            output_suffix("\t(retransmit)");
        }
        if (seq > stream->fwd->next_seq) {
            output_suffix("\t OOO sequece. maybe dropped packets: %d", seq - stream->fwd->seq);
        }
    }

    flow->seq = seq;
    if (data) {
        flow->next_seq = seq + 1;
    } else {
        flow->next_seq = seq;
    }
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
