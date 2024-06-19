#pragma once

#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t src_port; 
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reser:4;
    uint8_t data_off:4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint16_t sport() {
        return ntohs(src_port);
    }
    uint16_t dport() {
        return ntohs(dst_port);
    }

};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
