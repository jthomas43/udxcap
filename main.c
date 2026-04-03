
#include <assert.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "all.h"
#include "udx_conntrack.h"

// todo:
// 1.measure rtt. trickier than you might expect,
// with tcp it's the time for sending SYN, receiving SYN+ACK, and then sending
// ACK simply measuring from DATA to ACK is not enough, if we're on capturing
// host that's receiving that only measures the time spent processing technique:
// measure the time between the first DATA packet and the 11th data packet

#define FILTER_SZ 8192

char filter[FILTER_SZ];
int filter_sz;

struct sockaddr_storage src;
struct sockaddr_storage dst;

char srcstr[INET6_ADDRSTRLEN + 10 /*space for port #*/];
char dststr[INET6_ADDRSTRLEN + 10 /*space for port #*/];

struct timeval packet_time;

eth_hdr_t *eth;
ip4_hdr_t *ip4;
ip6_hdr_t *ip6;
udp_hdr_t *udp;

char line_buf[0x4000];
char *line;
int line_len;

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
    line_len += vsnprintf(line, sizeof(line_buf) - line_len, fmt, ap);
    assert(line_len >= 0);
    line = line_buf + line_len;

    va_end(ap);
}

typedef struct dht_request_s dht_request_t;

struct dht_request_s {
    int tid;
    bool internal;
    int command;

    dht_request_t *hash_next;
};

#define HASH_SIZE 1024

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

int
parse_ipv4 (const uint8_t *payload, int len);
int
parse_ipv6 (const uint8_t *payload, int len);
int
parse_udp (const uint8_t *payload, int len);
void
parse_appl (const uint8_t *payload, int len);
void
parse_udx (const uint8_t *payload, int len);

int dlt;
int packet_byte_size;

static size_t
addr_sizeof (struct sockaddr *sa) {
    assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);
    return sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

void
on_packet (u_char *ctx, const struct pcap_pkthdr *header, const u_char *payload) {

    line = line_buf;
    line_len = 0;

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

    payload += llhdr_size;
    int len = header->len - llhdr_size;
    int n = 0;

    if (proto == 0x800) {
        n = parse_ipv4(payload, len);
        if (ip4->protocol != 17) {
            return;
        }
    } else if (proto == 0x86dd) {
        n = parse_ipv6(payload, len);
        if (ip6->next_header != 17) {
            return;
        }
    } else {
        return;
    }

    payload += n;
    len -= n;
    n = parse_udp(payload, len);

    if (proto == 0x800) {
        struct sockaddr_in *s = (struct sockaddr_in *) &src;
        struct sockaddr_in *d = (struct sockaddr_in *) &dst;
        s->sin_port = udp->sport;
        d->sin_port = udp->dport;
    }
    if (proto == 0x86dd) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) &src;
        struct sockaddr_in6 *d = (struct sockaddr_in6 *) &dst;
        s->sin6_port = udp->sport;
        d->sin6_port = udp->dport;
    }

    char host[INET6_ADDRSTRLEN];
    char port[10];

    struct sockaddr *sa = (struct sockaddr *) &src;
    getnameinfo(sa, addr_sizeof(sa), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    snprintf(srcstr, sizeof(srcstr), "%15s:%-6s", host, port);

    sa = (struct sockaddr *) &dst;
    getnameinfo(sa, addr_sizeof(sa), host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    snprintf(dststr, sizeof(dststr), "%15s:%-6s", host, port);

    payload += n;
    len -= n;
    parse_appl(payload, len);

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
            udx_flow_t *f = established[i];
            while (f != NULL) {
                if (f->graph_file)
                    fclose(f->graph_file);
                f = f->hash_next;
            }
        }
    }

    return 0;
}

// returns: # of bytes of ip header,
// or -1 to drop packet
int
parse_ipv4 (const uint8_t *payload, int len) {
    ip4 = (ip4_hdr_t *) payload;
    ip6 = NULL;

    int version = ip4->v_and_hl >> 4;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    assert(version == 4);
    struct sockaddr_in *s = (struct sockaddr_in *) &src;
    struct sockaddr_in *d = (struct sockaddr_in *) &dst;
    s->sin_family = AF_INET;
    d->sin_family = AF_INET;
    s->sin_addr.s_addr = ip4->saddr;
    d->sin_addr.s_addr = ip4->daddr;

    int ip_header_len_bytes = (ip4->v_and_hl & 0xf) * 4; //
    int protocol = ip4->protocol;

    int ipv4_len = ntohs(ip4->tot_len);
    int flags_and_frag_offset = ntohs(ip4->frag_off);

    int flags = (flags_and_frag_offset >> 13) & 0x7;

    bool fragmented = flags & 0x1;
    int frag_offset = flags_and_frag_offset & 0x1fff;

    if (fragmented) {
        printf("fragment! ");
    }

    return ip_header_len_bytes;
}

int
parse_ipv6 (const uint8_t *payload, int len) {
    ip4 = NULL;
    ip6 = (ip6_hdr_t *) payload;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    struct sockaddr_in6 *s = (struct sockaddr_in6 *) &src;
    struct sockaddr_in6 *d = (struct sockaddr_in6 *) &dst;

    s->sin6_family = AF_INET6;
    d->sin6_family = AF_INET6;
    memcpy(&s->sin6_addr, &ip6->src, 16);
    memcpy(&d->sin6_addr, &ip6->dst, 16);

    int payload_len = ntohs(ip6->payload_len);

    return sizeof(ip6_hdr_t);
}

int
parse_udp (const uint8_t *payload, int len) {
    udp = (udp_hdr_t *) payload;

    return sizeof(udp_hdr_t);
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

typedef enum {
    DHT_REQ_FLAG_ID = 1,
    DHT_REQ_FLAG_TOKEN = 2,
    DHT_REQ_FLAG_INTERNAL = 4,
    DHT_REQ_FLAG_TARGET = 8,
    DHT_REQ_FLAG_VALUE = 16
} dht_request_flag_t;

typedef enum {
    DHT_RESP_FLAG_ID = 1,
    DHT_RESP_FLAG_TOKEN = 2,
    DHT_RESP_FLAG_CLOSER_NODES = 4,
    DHT_RESP_FLAG_ERROR = 8,
    DHT_RESP_FLAG_VALUE = 16
} dht_response_flag_t;

#define DHT_FLAG_ID    0b00001
#define DHT_FLAG_TOKEN 0b00010
#define DHT_FLAG_VALUE 0b10000

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

    output("%20s -> %20s DHT-RPC tid=%5d %s", srcstr, dststr, tid, request ? "REQ  " : "RESP ");

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
        uint64_t command = decode_compact_integer(&p);

        if (flags & DHT_REQ_FLAG_TARGET) {
            output("target=");
            print_bytes(p, 32);
            p += 32;
            output(" ");
        }

        bool internal = flags & DHT_REQ_FLAG_INTERNAL;

        if (command > 8 || (internal && command > 4)) {
            __builtin_trap();
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

        if (flags & DHT_RESP_FLAG_CLOSER_NODES) {
            uint64_t count = decode_compact_integer(&p);
            output("\ncloser nodes (%d):\n", count);

            for (int i = 0; i < count; i++) {
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, p, addr, sizeof(addr));
                p += 4;
                int port = p[0] + (p[1] << 8);
                p += 2;
                output("%4d: %15s:%-6d\n", i, addr, port);
            }
        }

        if (flags & DHT_RESP_FLAG_ERROR) {
            dht_rpc_error_t error = decode_compact_integer(&p);

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

    if (line_len > 0) {
        printf("%.*s\n", line_len, line_buf);
        line_len = 0;
    }
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

static int32_t
seq_cmp (uint32_t a, uint32_t b) {
    return a - b;
}

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

    output("%s -> %s UDX id=%10u seq=%10u ack=%10u", srcstr, dststr, id, seq, ack);

    int _flags = flags;

    bool print_flags = false;
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
                print_flags = true;
            }
        }
    }

    bool data = flags & UDX_HEADER_DATA;
    bool end = flags & UDX_HEADER_END;
    bool sack = flags & UDX_HEADER_SACK;
    bool message = flags & UDX_HEADER_MESSAGE;
    bool destroy = flags & UDX_HEADER_DESTROY;

    if (sack) {
        int sack_len_bytes = (data_offset > 0) ? data_offset : len;
        assert((sack_len_bytes % 8) == 0);
        for (int j = 0; j < sack_len_bytes; j += 8) {
            output(" %u:%u", i[0], i[1]);
            i += 2;
        }
    }

    payload += data_offset;
    len -= data_offset;

    if (data) {
        output(" Len=%d", len);
    }

    udx_flow_t *flow = upsert_flow((struct sockaddr *) &src, (struct sockaddr *) &dst, id);
    udx_stream_t *stream = get_stream(flow);

    if (flow->start_time.tv_sec == 0) {
        flow->start_time = packet_time;
        flow->time = packet_time;
    }

    if (opts.generate_graphs) {
        if (flow->graph_file == NULL) {
            char filename[120];
            snprintf(filename, 120, "%s_%s_%u.dat", srcstr, dststr, id);
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
    bool retransmit = false;
    int ooo_dropped = 0;

    if (data && flow->next_seq_valid && seq != flow->next_seq) {
        // should be seq_le, account for sequence wrap
        if (seq_cmp(seq, flow->next_seq) < 0) {
            flow->stat.retransmits++;
            retransmit = true;
        } else {
            ooo_dropped = seq - flow->seq;
        }
    }

    flow->seq = seq;
    if (data) {
        flow->next_seq_valid = true;
        flow->next_seq = seq + 1;
    } else {
        flow->next_seq = seq;
    }
    flow->ack = ack;
    flow->rwnd = rwnd;

    udx_flow_t *rev = get_reverse(flow);

    if (stream->complete) {
        int inflight = flow->seq - (rev->ack - 1);
    }

    if (data && opts.print_packet_bytes) {
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0) {
                output("\n\t");
            }
            output("%02x ", payload[i]);
        }
    }

    if (retransmit) {
        output(" Retransmit");
    }

    if (print_flags) {
        output("weird flags=%x)", flags);
    }
    if (ooo_dropped) {
        output("\nmissing %u packets", ooo_dropped);
    }

    if (line_len > 0) {
        printf("%.*s\n", line_len, line_buf);
        line_len = 0;
    }
}
