#ifndef PCAPSESSION_H
#define PCAPSESSION_H


#ifdef linux
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifdef WIN32
#endif


#include <pcap.h>
#include <QtCore>
#include "pcapsignal.h"


class pcapSession
{
    static pcap_t* adhandle;


    struct devInfo
    {

        QString descrip;

        QString addr_qstr;
        QString bcast_qstr;
        QString mask_qstr;

        u_int   addr_uint;
        u_int   bcast_uint;
        u_int   mask_uint;

    };


    static void legacyCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


public:

    // 4 bytes IP address
    struct ip_address{
        u_char byte1;
        u_char byte2;
        u_char byte3;
        u_char byte4;
    };


    // IPv4 header
    struct ip_header{
        u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
        u_char  tos;            // Type of service
        u_short tlen;           // Total length
        u_short identification; // Identification
        u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
        u_char  ttl;            // Time to live
        u_char  proto;          // Protocol
        u_short crc;            // Header checksum
        ip_address  saddr;      // Source address
        ip_address  daddr;      // Destination address
        u_int   op_pad;         // Option + Padding
    };


    // UDP header
    struct udp_header{
        u_short sport;          // Source port
        u_short dport;          // Destination port
        u_short len;            // Datagram length
        u_short crc;            // Checksum
    };


    // DNS header ( from RFC 1035 )
    struct dns_header{
        u_short id;
        u_short flags;      // qr  (1) + opcode (4) + aa (1) + tc (1) + rd (1) + ra (1) + z (3) + rcode(4)
        u_short qdcount;
        u_short ancount;
        u_short nscount;
        u_short arcount;
    };


    // TCP header ( from RFC 793 )
    struct tcp_header {
        u_short sport;              // Source port
        u_short dport;              // Destination port
        u_int seq;                  // Sequence number
        u_int ack;                  // Acknowledgment number

        u_char x2_off;              // Data offset (4 bits) + Reserved (4 bits)
                                    // Data offset - the number of 32 bit words in the TCP Header (the TCP header length)

        u_char flags;               // 8 flags (SYN, ACK, etc) x 1 bit
        u_short win;                // Window Size
        u_short sum;                // Checksum
        u_short urp;                // Urgent pointer
    };


    static pcapSignal helper;
    static QHash<QString, devInfo> allDevs;
    static QString addrConverter(const ip_address &addr);

    static void getAvailableDevices();
    static void startCapture(const char* captureDevName);
    static void stopCapture();
};


#endif // PCAPSESSION_H
