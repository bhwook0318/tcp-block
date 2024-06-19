#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <algorithm>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <cstring>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define FIN 0x1
#define SYN 0x2
#define RST 0x4
#define PUSH 0x08
#define ACK 0x16
#define URG 0x20

using std::cout;
using std::endl;
using std::search;
using std::string;

#pragma pack(push, 1)
typedef struct{
    Ip sip;
    Ip dip;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t len;
} Pseudo_hdr;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
} tcp_for;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct
{
    EthHdr ethHdr;
    IpHdr ipHdr;
    TcpHdr tcpHdr;
    char msg[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
} tcp_back;
#pragma pack(pop)

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

Mac get_my_Mac(char* dev)
{
    char mac_buf[18] = {0};
    int len = strlen(dev);
    int size = len + 24;
    char *path = (char *)malloc(size);
    if (path == NULL) exit(-1);
    snprintf(path, size, "%s%s%s", "/sys/class/net/", dev, "/address");
    int fd = open(path, O_RDONLY);
    if (fd == -1) exit(-1);
    int bytes = read(fd, mac_buf, 17);
    if (bytes != 17){
        free(path);
        close(fd);
        exit(-1);
    }
    free(path);
    close(fd);
    return Mac(mac_buf);
}

uint16_t cal_checksum(void* pkt, int size)
{
    uint16_t* buf = (uint16_t*)pkt;
    unsigned int cal_result = 0;
    
    while(size>1)
    {
        cal_result += *buf;
        buf++;
        size -= sizeof(uint16_t);
    }
    if (size) cal_result += *(uint16_t*)buf;
    cal_result = (cal_result >> 16) + (cal_result & 0xffff);
    cal_result += (cal_result >> 16);
    cal_result = ~cal_result;
    return cal_result;
}

uint16_t tcp_checksum(void* pkt, void* pseudo_pkt)
{
    uint16_t pse_tmp1 = ~cal_checksum(pseudo_pkt, sizeof(Pseudo_hdr));
    uint16_t pkt_size = ntohs(((Pseudo_hdr*)pseudo_pkt)->len);
    uint16_t pse_tmp2 = ~cal_checksum(pkt, pkt_size);
    uint32_t cal_result = pse_tmp1 + pse_tmp2;
    cal_result = (cal_result >> 16) + (cal_result & 0xffff);
    cal_result += (cal_result >> 16);
    cal_result = ~cal_result;
    return cal_result;
}

void block(pcap_t* handle, char* dev, const u_char* packet, char* pat)
{
    bool mode;
    PEthHdr ethHdr = (PEthHdr)packet;
    if (ethHdr->type() != EthHdr::Ip4) return;

    PIpHdr ipHdr = (PIpHdr)(packet + 14);
    if (ipHdr->protocol != 6) return;
    uint16_t iphdr_len = ((ipHdr->hln_ver) & 0xf) * 4;
    
    PTcpHdr tcpHdr = (PTcpHdr)((u_char*)ipHdr + iphdr_len);
    uint16_t dport = tcpHdr->dport();
    
    if (dport != 80 && dport != 443) return;
    else if (dport == 80) mode = true;
    else mode = false;

    uint16_t t_len = ipHdr->tlen();
    uint16_t tcphdr_len = (tcpHdr->data_off) * 4;

    uint32_t payload_len = t_len - (tcphdr_len + iphdr_len);
    if (payload_len == 0) return;

    string payload = string((char*)((u_char*)tcpHdr + tcphdr_len), payload_len);
    string target = string(pat,strlen(pat));

    Mac myMac = get_my_Mac(dev);
    tcp_back T_back;  
    tcp_for T_for;   

    T_back.ethHdr = *ethHdr;
    T_back.ipHdr = *ipHdr;
    T_back.tcpHdr = *tcpHdr;
    T_back.ethHdr.smac_ = myMac;
    T_back.ipHdr.dst_ip = ipHdr->src_ip;
    T_back.ipHdr.src_ip = ipHdr->dst_ip;
    T_back.ipHdr.ttl = 128;

    T_for.ethHdr = *ethHdr;
    T_for.ipHdr = *ipHdr;
    T_for.tcpHdr = *tcpHdr;
    T_for.ethHdr.smac_ = myMac;
    T_for.ipHdr.ttl = 128;
    
    uint16_t tmp = sizeof(IpHdr) + sizeof(TcpHdr);
    if (mode) T_back.ipHdr.tot_len = htons(tmp + 56);
    else T_back.ipHdr.tot_len = htons(tmp);
    T_for.ipHdr.tot_len = htons(tmp);
    
    T_back.tcpHdr.data_off = (sizeof(TcpHdr) * 4);
    T_back.tcpHdr.dst_port = tcpHdr->src_port;
    T_back.tcpHdr.src_port = tcpHdr->dst_port;
    
    T_for.tcpHdr.data_off = (sizeof(TcpHdr) * 4);
    T_for.tcpHdr.flags = (RST|ACK);
    
    if (mode) T_back.tcpHdr.flags = (FIN|ACK);
    else T_back.tcpHdr.flags = (RST|ACK);

    T_back.tcpHdr.seq_num = tcpHdr->ack_num;
    T_back.tcpHdr.ack_num = htonl(ntohl(tcpHdr->seq_num) + payload_len);
    T_back.ipHdr.checksum = T_back.tcpHdr.checksum = 0;
    T_back.ipHdr.checksum = cal_checksum(&(T_back.ipHdr), sizeof(IpHdr));
    
    T_for.tcpHdr.seq_num = htonl(ntohl(tcpHdr->seq_num) + payload_len);
    T_for.ipHdr.checksum = T_for.tcpHdr.checksum = 0; 
    T_for.ipHdr.checksum = cal_checksum(&(T_for.ipHdr), sizeof(IpHdr));

    Pseudo_hdr P_back;
    Pseudo_hdr P_for;
        
    P_back.dip = T_back.ipHdr.dst_ip;
    P_back.sip = T_back.ipHdr.src_ip;
    P_back.reserved = 0;
    P_back.protocol = 6;

    P_for.dip = T_for.ipHdr.dst_ip;
    P_for.sip = T_for.ipHdr.src_ip;
    P_for.reserved = 0;
    P_for.protocol = 6;
    
    P_for.len = htons(sizeof(TcpHdr));
    T_for.tcpHdr.checksum = tcp_checksum(&(T_for.tcpHdr),&(P_for));
    if (mode) P_back.len = htons(56 + sizeof(TcpHdr));
    else P_back.len = htons(sizeof(TcpHdr));
    T_back.tcpHdr.checksum = tcp_checksum(&(T_back.tcpHdr),&(P_back));
    
    if (mode) pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&T_back), sizeof(T_back));
    else pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&T_back), sizeof(T_for));
    pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&T_for), sizeof(T_for));
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
	usage();
	return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            cout << "pcap_next_ex return "<< res <<'('<< pcap_geterr(handle) << ')' << endl;
            break;
        }
        block(handle, argv[1], packet, argv[2]);
    }

    pcap_close(handle);

    return 0;
}
