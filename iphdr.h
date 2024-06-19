#pragma once

#include <stdio.h>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t hln_ver;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    Ip src_ip;
    Ip dst_ip;
    
    uint32_t sip() {
        return ntohl(src_ip);
    }
    uint32_t dip() {
        return ntohl(dst_ip);
    }
    uint16_t tlen() {
        return ntohs(tot_len);
    }
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
