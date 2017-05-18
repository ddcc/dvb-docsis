#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>
#include <linux/limits.h>

#include "dvb-docsis.h"

#define ARRAY_SIZE(x)   (sizeof(x)/sizeof(*(x)))

// libevent structures
struct evconnlistener *ev_socket = NULL;
struct event *ev_demux = NULL;
struct bufferevent *ev_stats = NULL;
struct event_base *events = NULL;

char clients_ip[MAX_CLIENTS][INET6_ADDRSTRLEN] = { { 0 } };
struct bufferevent *clients[MAX_CLIENTS] = { NULL };

uint8_t *buffer = NULL;
size_t buffer_size = 0;

// state variables
int frontend_fd = -1;
int demux_fd = -1;
int loop = 1;

uint32_t pid = MPEG2_PID_DOCSIS;
int raw = 0;

// Clean up libevent by deallocating it
void cleanup_event() {
    if (buffer || buffer_size) {
        buffer_size = 0;
        free(buffer);
        buffer = NULL;
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i]) {
            bufferevent_free(clients[i]);
            clients[i] = NULL;
        }
    }

    if (ev_socket) {
        evconnlistener_free(ev_socket);
        ev_socket = NULL;
    }

    if (ev_stats) {
        bufferevent_free(ev_stats);
        ev_stats = NULL;
    }

    if (ev_demux) {
        event_free(ev_demux);
        ev_demux = NULL;
    }

    if (events) {
        event_base_free(events);
        events = NULL;
    }
}

// Clean up the demux by stopping it and closing the fd
void cleanup_demux() {
    if (demux_fd != -1) {
        ioctl(demux_fd, DMX_STOP, 0);
        close(demux_fd);
        demux_fd = -1;
    }
}

// Clean up the frontend by closing the fd
void cleanup_frontend() {
    if (frontend_fd != -1) {
        close(frontend_fd);
        frontend_fd = -1;
    }
}

// Check whether the specified modulation scheme is supported by the frontend
int check_capabilities(const enum fe_modulation modulation, const enum fe_caps capabilities) {
    enum fe_caps mask;

    switch (modulation) {
        case QPSK:
            mask = FE_CAN_QPSK;
        break;
        case QAM_16:
            mask = FE_CAN_QAM_16;
        break;
        case QAM_32:
            mask = FE_CAN_QAM_32;
        break;
        case QAM_64:
            mask = FE_CAN_QAM_64;
        break;
        case QAM_128:
            mask = FE_CAN_QAM_128;
        break;
        case QAM_256:
            mask = FE_CAN_QAM_256;
        break;
        case QAM_AUTO:
            mask = FE_CAN_QAM_AUTO;
        break;
        case VSB_8:
            mask = FE_CAN_8VSB;
        break;
        case VSB_16:
            mask = FE_CAN_16VSB;
        break;
        case PSK_8:
        case APSK_16:
        case APSK_32:
        case DQPSK:
        case QAM_4_NR:
        default:
            mask = 0;
        break;
    }

    return ((mask & capabilities) == mask);
}

// Print out a specific statistic
void print_stat(const char *str, const struct dtv_fe_stats *stat) {
    if (stat && stat->len > 0 && stat->stat[0].scale != FE_SCALE_NOT_AVAILABLE) {
        printf("%s", str);
        switch (stat->stat[0].scale) {
            case FE_SCALE_DECIBEL:
                printf("%fdB", stat->stat[0].svalue / 1000.);
            break;
            case FE_SCALE_RELATIVE:
                printf("%f%%", (100. * stat->stat[0].uvalue) / 65535.);
            break;
            case FE_SCALE_COUNTER:
                printf("%" PRIu64, stat->stat[0].uvalue);
            break;
        }
    }
}

// Print out statistics on the frontend using the libevent API
void stdin_read(struct bufferevent *bev, void *ctx) {
    struct dtv_property props[] = {
        { .cmd = DTV_STAT_SIGNAL_STRENGTH },
        { .cmd = DTV_STAT_CNR },
        { .cmd = DTV_STAT_PRE_ERROR_BIT_COUNT },
        { .cmd = DTV_STAT_PRE_TOTAL_BIT_COUNT },
        { .cmd = DTV_STAT_POST_ERROR_BIT_COUNT },
        { .cmd = DTV_STAT_POST_TOTAL_BIT_COUNT },
        { .cmd = DTV_STAT_ERROR_BLOCK_COUNT },
        { .cmd = DTV_STAT_TOTAL_BLOCK_COUNT },
    };
    struct dtv_properties dp = {
        .num = ARRAY_SIZE(props),
        .props = props,
    };
    static int v5 = 1;

    struct evbuffer *in_buf = bufferevent_get_input(bev);
    evbuffer_drain(in_buf, evbuffer_get_length(in_buf));

    if (v5) {
        if (frontend_fd == -1 || ioctl(frontend_fd, FE_GET_PROPERTY, &dp) == -1) {
            perror("!! Error");
            goto out_err;
        }

        // If all the properties have length zero, then DVB API v5 statistics are not supported
        for (int i = 0; i < dp.num; i++) {
            if (dp.props[i].u.st.len) {
                v5 = 1;
                goto cont;
            }
        }

        v5 = 0;
    }

cont:
    // If v5 not supported, fall back to legacy DVB API v3
    if (v5) {
        printf(">> Frontend: ");
        print_stat("Signal Strength: ", &props[0].u.st);
        print_stat(", Carrier SNR: ", &props[1].u.st);
        print_stat(", Pre-FEC Errors: ", &props[2].u.st);
        print_stat(", Pre-FEC Total Errors: ", &props[3].u.st);
        print_stat(", Post-FEC Errors: ", &props[4].u.st);
        print_stat(", Post-FEC Total Errors: ", &props[5].u.st);
        print_stat(", Block Errors: ", &props[6].u.st);
        print_stat(", Block Total Errors: ", &props[7].u.st);
        printf("\n");
    } else {
        if (ioctl(frontend_fd, FE_READ_SIGNAL_STRENGTH, &props[0].u.st.stat[0].uvalue) == -1) {
            perror("!! Error");
            goto out_err;
        }
        props[0].u.st.len = 1;
        props[0].u.st.stat[0].scale = FE_SCALE_RELATIVE;

        if (ioctl(frontend_fd, FE_READ_SNR, &props[1].u.st.stat[0].uvalue) == -1) {
            perror("!! Error");
            goto out_err;
        }
        props[1].u.st.len = 1;
        props[1].u.st.stat[0].scale = FE_SCALE_RELATIVE;

        if (ioctl(frontend_fd, FE_READ_BER, &props[2].u.st.stat[0].uvalue) == -1) {
            perror("!! Error");
            goto out_err;
        }
        props[2].u.st.len = 1;
        props[2].u.st.stat[0].scale = FE_SCALE_COUNTER;

        if (ioctl(frontend_fd, FE_READ_UNCORRECTED_BLOCKS, &props[3].u.st.stat[0].uvalue) == -1) {
            perror("!! Error");
            goto out_err;
        }
        props[3].u.st.len = 1;
        props[3].u.st.stat[0].scale = FE_SCALE_COUNTER;

        printf(">> Statistics: ");
        print_stat("Signal Strength: ", &props[0].u.st);
        print_stat(", Carrier SNR: ", &props[1].u.st);
        print_stat(", Block Error Rate: ", &props[2].u.st);
        print_stat(", Uncorrected Blocks: ", &props[3].u.st);
        printf("\n");
    }

    return;

out_err:
    bufferevent_disable(ev_stats, EV_READ);
}

// Handle socket errors on the network clients using the libevent API
void socket_error(struct bufferevent *bev, short error, void *ctx) {
    int i = 0;
    char *ip = NULL;

    // If a client disconnected, free the connection and clear its entry
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == bev) {
            bufferevent_free(clients[i]);
            clients[i] = NULL;

            ip = clients_ip[i];
            break;
        }
    }

    if (!ip) {
        fprintf(stderr, "!! Error: Cannot find client %p!\n", bev);
        event_base_loopbreak(events);
        return;
    }

    fprintf(stderr, "!! Client [%s]: Error: %s\n", ip, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

// Handle new clients on the network listener using the libevent API
void socket_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx) {
    int i = 0;
    struct pcap_file_header pcap;
    struct bufferevent **client = NULL;

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            client = &clients[i];
            break;
        }
    }

    if (!client) {
        fprintf(stderr, "!! Error: Reached maximum client limit (%d)!\n", MAX_CLIENTS);
        event_base_loopbreak(events);
        return;
    }

    inet_ntop(AF_INET6, &((struct sockaddr_in6 *) address)->sin6_addr, clients_ip[i], sizeof(clients_ip[i]));
    printf(">> Client [%s]: Connected\n", clients_ip[i]);

    *client = bufferevent_socket_new(events, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(*client, NULL, NULL, socket_error, NULL);

    if (!raw) {
        pcap.magic = TCPDUMP_MAGIC;
        pcap.version_major = PCAP_VERSION_MAJOR;
        pcap.version_minor = PCAP_VERSION_MINOR;
        pcap.thiszone = 0;
        pcap.sigfigs = 0;
        pcap.snaplen = 65535;
        pcap.linktype = LINKTYPE_MPEG_2_TS;

        bufferevent_write(*client, &pcap, sizeof(pcap));
    }

    bufferevent_enable(*client, EV_READ | EV_WRITE);
}

// Handle errors on the network listener using the libevent API
void socket_accept_error(struct evconnlistener *listener, void *ctx) {
    fprintf(stderr, "!! Error: %s!\n", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    event_base_loopbreak(events);
}

// Handle pcap reads on the demux using the libevent API
void demux_read_pcap(struct evbuffer *in_buf) {
    mpeg2_ts_t *mpeg2 = (mpeg2_ts_t *) buffer;
    int n, len = evbuffer_get_length(in_buf);
    struct evbuffer *out_buf;
    struct pcap_pkthdr pcap = {
        .caplen = MPEG2_TS_SIZE,
        .len = MPEG2_TS_SIZE,
    };

    // Allocate if buffer empty
    if (!buffer_size) {
        buffer = malloc(MPEG2_TS_SIZE);
        buffer_size = MPEG2_TS_SIZE;

        mpeg2 = (mpeg2_ts_t *) buffer;
    }

    while (len >= MPEG2_TS_SIZE) {
        // Need to find valid packet; copy in the header
        do {
            evbuffer_remove(in_buf, buffer, sizeof(*mpeg2));
            len -= sizeof(*mpeg2);

            if (mpeg2->sync == MPEG2_TS_SYNC && (MPEG2_TS_PID(mpeg2) == pid || pid == MPEG2_PID_ANY)) {
                break;
            }

            // fprintf(stderr, "!! Warning: Discarding %d bytes while finding MPEG2-TS sync!\n", sizeof(*mpeg2));
        } while (len >= sizeof(*mpeg2));

        // Check that there is enough remaining data
        if (len < MPEG2_TS_SIZE - sizeof(*mpeg2)) {
            break;
        }

        // Set the time in the PCAP header
        gettimeofday(&pcap.ts, NULL);

        // Copy in the data
        if ((n = evbuffer_remove(in_buf, buffer + sizeof(*mpeg2), MPEG2_TS_SIZE - sizeof(*mpeg2))) == -1 || n != MPEG2_TS_SIZE - sizeof(*mpeg2)) {
            fprintf(stderr, "!! Error: Cannot remove data from input buffer!\n");
            event_base_loopbreak(events);
            return;
        }

        len -= MPEG2_TS_SIZE - sizeof(*mpeg2);

        // Look for connected clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i]) {
                continue;
            }

            // Get the client's output buffer
            out_buf = bufferevent_get_output(clients[i]);

            // Prepend the PCAP packet header
            if (evbuffer_add(out_buf, &pcap, sizeof(pcap))) {
                fprintf(stderr, "!! Error: Cannot prepend PCAP header to output buffer!\n");
                event_base_loopbreak(events);
                return;
            }

            // Copy out the packet
            if (evbuffer_add(out_buf, buffer, MPEG2_TS_SIZE) == -1) {
                fprintf(stderr, "!! Error: Cannot copy packet data to output buffer!\n");
                event_base_loopbreak(events);
                return;
            }
        }
    }
}

// Handle raw reads on the demux
void demux_read_raw(struct evbuffer *in_buf) {
    size_t len = evbuffer_get_length(in_buf);
    struct evbuffer *out_buf;
    int n;

    // Reallocate if larger buffer is needed
    if (buffer_size < len) {
        buffer = realloc(buffer, len * sizeof(*buffer));
        buffer_size = len;
    }

    // Copy in the data
    if ((n = evbuffer_remove(in_buf, buffer, len)) == -1) {
        fprintf(stderr, "!! Error: Cannot remove data from input buffer!\n");
        event_base_loopbreak(events);
        return;
    }

    // Look for connected clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            continue;
        }

        // Get the client's output buffer
        out_buf = bufferevent_get_output(clients[i]);

        // Copy out the data
        if (evbuffer_add(out_buf, buffer, n) == -1) {
            fprintf(stderr, "!! Error: Cannot copy data to output buffer!\n");
            event_base_loopbreak(events);
            return;
        }
    }
}

// Handle reads on the demux and wrap it into a evbuffer. Can't use evbuffer_read(), because it will limit the maximum read amount to EVBUFFER_MAX_READ, which isn't enough to avoid EOVERFLOW.
void demux_read(evutil_socket_t fd, short event, void *arg) {
    struct evbuffer *in = (struct evbuffer *) arg;
    struct evbuffer_iovec iovec[MAX_READ_IOVEC];
    int read_len, actual_len, n;

    if (!arg) {
        fprintf(stderr, "!! Error: Cannot obtain output buffer!\n");
        event_base_loopbreak(events);
        return;
    }

    // Get amount of data available, otherwise fall back to fixed read amount
    if (ioctl(fd, FIONREAD, &read_len) == -1) {
        if (errno == EINVAL) {
            fprintf(stderr, "!! Warning: Falling back to default read size of %d!\n", MAX_READ_FALLBACK);
            read_len = MAX_READ_FALLBACK;
        } else if (errno == EOVERFLOW) {
            fprintf(stderr, "!! Error: Kernel ringbuffer has overflowed!\n");
            event_base_loopbreak(events);
            return;
        } else {
            perror("!! Error");
            event_base_loopbreak(events);
            return;
        }
    }

    // Reserve the space
    if ((n = evbuffer_reserve_space(in, read_len, iovec, MAX_READ_IOVEC)) == -1) {
        fprintf(stderr, "!! Error: Cannot allocate buffer space!\n");
        event_base_loopbreak(events);
        return;
    }

    // Perform the read
    if ((actual_len = readv(fd, iovec, n)) == -1) {
        perror("!! Error");
        event_base_loopbreak(events);
        return;
    }

    // A fallback fixed amount was used, but actually less data was available
    if (actual_len < read_len) {
        // Need to modify the corresponding iovec with the actual read amount
        for (int i = 0; i < n; i++) {
            if (iovec[i].iov_len <= actual_len) {
                actual_len -= iovec[i].iov_len;
            } else {
                iovec[i].iov_len = actual_len;
                actual_len = 0;
                break;
            }
        }

        if (actual_len) {
            fprintf(stderr, "!! Error: Cannot set amount of data read!\n");
            event_base_loopbreak(events);
            return;
        }
    }

    // Commit the data
    if (evbuffer_commit_space(in, iovec, n) == -1) {
        fprintf(stderr, "!! Error: Cannot commit data to input buffer!\n");
        event_base_loopbreak(events);
        return;
    }

    // Call the event handlers
    if (raw) {
        demux_read_raw(in);
    } else {
        demux_read_pcap(in);
    }
}

// Configure the libevent API to handle events
int init_event(const struct in6_addr *host, const uint32_t port) {
    int ret = 0;
    struct sockaddr_in6 sin = {
        .sin6_family = AF_INET6,
        .sin6_addr = *host,
        .sin6_port = htons(port),
    };

    if (events || !(events = event_base_new())) {
        ret = -1;
        goto out_err;
    }

    // Add the statistics printout
    if (ev_stats || !(ev_stats = bufferevent_socket_new(events, STDIN_FILENO, 0))) {
        ret = -1;
        goto out_err;
    }
    bufferevent_setcb(ev_stats, stdin_read, NULL, NULL, NULL);
    bufferevent_enable(ev_stats, EV_READ);

    // Add the socket listener
    if (ev_socket || !(ev_socket = evconnlistener_new_bind(events, socket_accept, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr *) &sin, sizeof(sin)))) {
        ret = -1;
        goto out_err;
    }
    evconnlistener_set_error_cb(ev_socket, socket_accept_error);

    // Add the demux read, using event instead of bufferevent because EVBUFFER_MAX_READ can cause the underlying socket to return EOVERFLOW
    if (demux_fd == -1 || ev_demux || !(ev_demux = event_new(events, demux_fd, EV_READ | EV_PERSIST, demux_read, evbuffer_new()))) {
        ret = -1;
        goto out_err;
    }
    event_add(ev_demux, NULL);

    goto out;

out_err:
    cleanup_event();
out:
    return ret;
}

// Configure the MPEG-2 demuxer to filter packets with a specific id (PID)
int init_demux(const unsigned int adapter, const unsigned int pid) {
    int ret = 0;
    char demux[PATH_MAX];
    struct dmx_pes_filter_params dpf = {
        .pid = pid,
        .input = DMX_IN_FRONTEND,
        .output = DMX_OUT_TSDEMUX_TAP,
        .pes_type = DMX_PES_OTHER,
        .flags = 0,
    };

    snprintf(demux, sizeof(demux), DVB_DEMUX_PATH, adapter);
    if (demux_fd != -1 || (demux_fd = open(demux, O_RDWR | O_NONBLOCK)) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    // Increase the buffer size to prevent EOVERFLOW from dmxdev
    if (ioctl(demux_fd, DMX_SET_BUFFER_SIZE, 20 * 4096) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    if (ioctl(demux_fd, DMX_SET_PES_FILTER, &dpf) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    printf(">> Demux: PID: 0x%x\n", pid);
    goto out;

out_err:
    cleanup_demux();
out:
    return ret;
}

// Check frontend capabilities and tune it to a specific frequency using a modulation scheme and standard
int init_frontend(const unsigned int adapter, const enum fe_delivery_system standard, const uint32_t frequency, const enum fe_modulation modulation) {
    int ret = 0;
    enum fe_status status;
    char frontend[PATH_MAX];
    struct dvb_frontend_info dfi;
    struct dtv_property props[] = {
        { .cmd = DTV_CLEAR },
        { .cmd = DTV_DELIVERY_SYSTEM, .u.data = standard },
        { .cmd = DTV_FREQUENCY,       .u.data = frequency },
        { .cmd = DTV_MODULATION,      .u.data = modulation },
        { .cmd = DTV_SYMBOL_RATE,     .u.data = (standard == SYS_DVBC_ANNEX_B) ? (modulation & QAM_64 ? DOCSIS_QAM64_SYMBOL_RATE : DOCSIS_QAM256_SYMBOL_RATE) : EURODOCSIS_SYMBOL_RATE },
        { .cmd = DTV_INVERSION,       .u.data = INVERSION_AUTO },
        { .cmd = DTV_INNER_FEC,       .u.data = FEC_AUTO },
        { .cmd = DTV_TUNE },
    };
    struct dtv_properties dp = {
        .num = ARRAY_SIZE(props),
        .props = props,
    };

    snprintf(frontend, sizeof(frontend), DVB_FRONTEND_PATH, adapter);
    if (frontend_fd != -1 || (frontend_fd = open(frontend, O_RDWR)) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    if (ioctl(frontend_fd, FE_GET_INFO, &dfi) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    if (frequency > dfi.frequency_max || frequency < dfi.frequency_min) {
        fprintf(stderr, "Error: Unsupported frequency '%u' Hz, supported range: '%u' - '%u' Hz\n", frequency, dfi.frequency_min, dfi.frequency_max);
        ret = -1;
        goto out_err;
    }

    if ((frequency % dfi.frequency_stepsize) != 0) {
        fprintf(stderr, "Error: Unsupported frequency step, must be multiple of '%u' Hz\n", dfi.frequency_stepsize);
        ret = -1;
        goto out_err;
    }

    if (!check_capabilities(modulation, dfi.caps)) {
        fprintf(stderr, "Error: Unsupported modulation scheme, supported capabilities '0x%x'\n", dfi.caps);
        ret = -1;
        goto out_err;
    }

    printf("Using frontend '%s'...\n", dfi.name);
    printf(">> Frontend: DTV_DELIVERY_SYSTEM: 0x%x, DTV_FREQUENCY: %u Hz, DTV_MODULATION: 0x%x, DTV_SYMBOL_RATE: %u sym/s\n", props[1].u.data, props[2].u.data, props[3].u.data, props[4].u.data);

    if (ioctl(frontend_fd, FE_SET_PROPERTY, &dp) == -1) {
        perror("!! Error");
        ret = -1;
        goto out_err;
    }

    do {
        printf(">> Frontend: Waiting for lock ... ");

        if (ioctl(frontend_fd, FE_READ_STATUS, &status) == -1) {
            perror("!! Error");
            ret = -1;
            goto out_err;
        }

        printf("0x%x (", status);
        if (status & FE_HAS_SIGNAL) printf(" FE_HAS_SIGNAL ");
        if (status & FE_HAS_CARRIER) printf(" FE_HAS_CARRIER ");
        if (status & FE_HAS_VITERBI) printf(" FE_HAS_VITERBI ");
        if (status & FE_HAS_SYNC) printf(" FE_HAS_SYNC ");
        if (status & FE_HAS_LOCK) printf(" FE_HAS_LOCK ");
        printf(")\n");
        fflush(stdout);
        sleep(1);
    } while (loop && !(status & FE_HAS_LOCK));

    if (status & FE_HAS_LOCK) {
        printf("... Success!\n");
    } else {
        ret = -1;
    }

    goto out;

out_err:
    cleanup_frontend();
out:
    return ret;
}

int print_usage(char* argv0) {
    printf("Usage: %s [-a <adapter = 0>] [-d <delivery = DVB-C-B (DVB-C-B|DVB-C-A|ATSC)] [-h <bind address = ::0>] [-l <port = %d>] [-m <modulation = QAM256 (QAM64|QAM256|QPSK|VSB8)>] [-p <demux filter = 0x1ffe>] [-s <stream type = pcap (raw|pcap)>] [-z <frequency = 591000000 Hz>]\n", argv0, DEFAULT_LISTEN_PORT);
    return -1;
}

void cleanup() {
    cleanup_event();
    cleanup_demux();
    cleanup_frontend();
}

void signal_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        loop = 0;
    }

    event_base_loopbreak(events);
}

int main(int argc, char** argv) {
    enum fe_caps modulation = QAM_256;
    struct in6_addr addr = DEFAULT_BIND_ADDR;
    enum fe_delivery_system standard = SYS_DVBC_ANNEX_B;
    uint32_t adapter = 0, frequency = DEFAULT_FREQUENCY, port = DEFAULT_LISTEN_PORT;
    struct sigaction action = {
        .sa_handler = signal_handler,
    };
    int c;

    while (1) {
        if ((c = getopt(argc, argv, "a:d:h:l:m:p:s:z:")) == -1) {
            break;
        }

        switch (c) {
            case '?':
                return print_usage(argv[0]);
            break;
            case 'a':
                adapter = strtoul(optarg, NULL, 0);
            break;
            case 'd':
                if (!strcmp(optarg, "DVB-C-B")) {
                    standard = SYS_DVBC_ANNEX_B;
                } else if (!strcmp(optarg, "DVB-C-A")) {
                    standard = SYS_DVBC_ANNEX_A;
                } else if (!strcmp(optarg, "ATSC")) {
                    standard = SYS_ATSC;
                } else {
                    return print_usage(argv[0]);
                }
            break;
            case 'h':
                if (inet_pton(AF_INET6, optarg, &addr) == -1) {
                    perror("!! Error");
                    return print_usage(argv[0]);
                }
            break;
            case 'l':
                port = strtoul(optarg, NULL, 0);
            break;
            case 'm':
                if (!strcmp(optarg, "QAM64")) {
                    modulation = QAM_64;
                } else if (!strcmp(optarg, "QAM256")) {
                    modulation = QAM_256;
                } else if (!strcmp(optarg, "QPSK")) {
                    modulation = QPSK;
                } else if (!strcmp(optarg, "VSB8")) {
                    modulation = VSB_8;
                } else {
                    return print_usage(argv[0]);
                }
            break;
            case 'p':
                pid = strtoul(optarg, NULL, 0);
            break;
            case 's':
                if (!strcmp(optarg, "raw")) {
                    raw = 1;
                } else if (!strcmp(optarg, "pcap")) {
                    raw = 0;
                } else {
                    return print_usage(argv[0]);
                }
            break;
            case 'z':
                frequency = strtoul(optarg, NULL, 0);
            break;
            default:
                return print_usage(argv[0]);
            break;
        }
    }

    // Setup signal handlers
    if (sigaction(SIGINT, &action, NULL) == -1 || sigaction(SIGTERM, &action, NULL) == -1) {
        perror("!! Error");
        return -1;
    }

    // Configure the frontend
    if (init_frontend(adapter, standard, frequency, modulation) == -1) {
        return -1;
    }

    // Configure the demux
    if (init_demux(adapter, pid) == -1) {
        return -1;
    }

    // Configure event processing
    if (init_event(&addr, port) == -1) {
        return -1;
    }

    // Enable the demux
    if (ioctl(demux_fd, DMX_START, 0) == -1) {
        return -1;
    }

    // Perform event handling
    event_base_dispatch(events);

    printf("Exiting...\n");
    cleanup();

    return errno ? -1 : 0;
};
