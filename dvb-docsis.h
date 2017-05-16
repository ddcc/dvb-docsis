#ifndef __DVB_DOCSIS_H__
#define __DVB_DOCSIS_H__ 1

#define DVB_DEMUX_PATH              "/dev/dvb/adapter%u/demux0"
#define DVB_FRONTEND_PATH           "/dev/dvb/adapter%u/frontend0"

// PCAP
#define LINKTYPE_DOCSIS             143
#define LINKTYPE_MPEG_2_TS          243
#define TCPDUMP_MAGIC               0xa1b2c3d4

// ITU-T J.83 Annex B, CM-SP-PHYv3.0-I08-090121
#define DOCSIS_QAM64_SYMBOL_RATE    5056941
#define DOCSIS_QAM256_SYMBOL_RATE   5360537
#define EURODOCSIS_SYMBOL_RATE      6952000

// MPEG-2 Transport Stream
#define MPEG2_PID_ANY               0x2000
#define MPEG2_PID_DOCSIS            0x1ffe
#define MPEG2_PID_NULL              0x1fff
#define MPEG2_TS_SYNC               0x47
#define MPEG2_TS_SIZE               188

#define MPEG2_TS_ADAPTATION(x)      (x->header[2] & 0x20)
#define MPEG2_TS_PAYLOAD(x)         (x->header[2] & 0x10)
#define MPEG2_TS_CC(x)              (x->header[2] & 0x0f)
#define MPEG2_TS_TEI(x)             (x->header[0] & 0x80)
#define MPEG2_TS_PID(x)             (((x->header[0] & 0x1f) << 8)| x->header[1])
#define MPEG2_TS_PUSI(x)            (x->header[0] & 0x40)
#define MPEG2_TS_SCRAMBLING(x)      (x->header[2] & 0xc0)

typedef struct {
    uint8_t sync;
    uint8_t header[3];
} mpeg2_ts_t;

// Configuration Options
#define DEFAULT_BIND_ADDR           IN6ADDR_ANY_INIT
#define DEFAULT_FREQUENCY           591000000
#define DEFAULT_LISTEN_PORT         7777

#define BUFFER_SIZE                 10 * 1024 * MPEG2_TS_SIZE
#define MAX_CLIENTS                 8
#define MAX_READ_FALLBACK           8192
#define MAX_READ_IOVEC              4

#endif
