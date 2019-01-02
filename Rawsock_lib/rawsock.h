// Rawsock_lib, licensed under GPLv2
// 2018-01-02, version 0.1, supporting IP and UDP
#ifndef RAWSOCK_H_INCLUDED
#define RAWSOCK_H_INCLUDED

#include <net/ethernet.h>
#include <linux/udp.h>	
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#define MAC_FILE_PATH_SIZE 23
#define MAC_ADDR_SIZE 6

// Errors
#define ERR_WLAN_NOIF 0 // No WLAN interfaces
#define ERR_WLAN_SOCK -1 // socket() creation error
#define ERR_WLAN_GETIFADDRS -2 // getifaddrs() error
#define ERR_WLAN_INDEX -3 // Wrong index specified
#define ERR_WLAN_GETSRCMAC -4 // Unable to get source MAC address (if requested)
#define ERR_WLAN_GETIFINDEX -5 // Unable to get source interface index (if requested)

#define ERR_IPHEADP_SOCK -10 // socket() creation error
#define ERR_IPHEAD_NOSRCADDR -11 // Unable to retrieve current device IP address

// Names
#define MAC_NULL 0x00
#define MAC_BROADCAST 0x01
#define MAC_UNICAST 0x02
#define MAC_MULTICAST 0x03

// Useful constants
// Additional EtherTypes
#define ETHERTYPE_GEONET 0x8947
#define ETHERTYPE_WSMP 0x88DC

// IP constants
#define BASIC_IHL 5
#define IPV4 4
#define BASIC_UDP_TTL 64 // From Wireshark captures

// UDP constant
#define UDPHEADERLEN 8

// Useful masks
#define FLAG_NOFRAG_MASK (1<<6)
#define FLAG_RESERVED_MASK (1<<7)
#define FLAG_MOREFRAG_MASK (1<<5)

// Checksum protocols, to be used inside the validateCsum() function 
//  (0x00->0x7F should be simple types, 0x80->0xFF should be combined types)
#define CSUM_IP 0x00
#define CSUM_UDP 0x01
#define CSUM_UDPIP 0x80

// Size definitions (macros)
#define UDP_PACKET_SIZE(data) sizeof(struct udphdr)+strlen(argv[5])
#define IP_UDP_PACKET_SIZE(data) sizeof(struct iphdr)+sizeof(struct udphdr)+strlen(argv[5])
#define ETH_IP_UDP_PACKET_SIZE(data) sizeof(struct iphdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+strlen(argv[5])

typedef unsigned char * macaddr_t;
typedef unsigned short ethertype_t;
typedef unsigned char byte_t;
typedef int rawsockerr_t;
typedef unsigned char csumt_t;
typedef __sum16 csum16_t;
struct ipaddrs {
	in_addr_t src;
	in_addr_t dst;
};

// General utilities
rawsockerr_t wlanLookup(char *devname, int *ifindex, macaddr_t mac, unsigned int index);
macaddr_t prepareMacAddrT();
unsigned int macAddrTypeGet(macaddr_t mac);
void freeMacAddrT(macaddr_t mac);
void rs_printerror(FILE *stream,rawsockerr_t code);
void display_packet(const char *text,byte_t *packet,unsigned int len);
void display_packetc(const char *text,byte_t *packet,unsigned int len);

// Ethernet level functions
void etherheadPopulateB(struct ether_header *etherHeader, macaddr_t mac, ethertype_t type);
void etherheadPopulate(struct ether_header *etherHeader, macaddr_t macsrc, macaddr_t macdst, ethertype_t type);
size_t etherEncapsulate(byte_t *packet,struct ether_header *header,byte_t *sdu,size_t sdusize);

// IP level functions
rawsockerr_t IP4headPopulateB(struct iphdr *IPhead, char *devname,unsigned char tos,unsigned short frag_offset, unsigned char ttl, unsigned char protocol,unsigned int flags,struct ipaddrs *addrs);
rawsockerr_t IP4headPopulate(struct iphdr *IPhead, char *devname, char *destIP, unsigned char tos,unsigned short frag_offset, unsigned char ttl, unsigned char protocol,unsigned int flags,struct ipaddrs *addrs);
void IP4headAddID(struct iphdr *IPhead, unsigned short id);
void IP4headAddTotLen(struct iphdr *IPhead, unsigned short len);
size_t IP4Encapsulate(byte_t *packet,struct iphdr *header,byte_t *sdu,size_t sdusize);

// UDP level functions
void UDPheadPopulate(struct udphdr *UDPhead, unsigned short sourceport, unsigned short destport);
size_t UDPencapsulate(byte_t *packet,struct udphdr *header,char *data,size_t payloadsize,struct ipaddrs addrs);

// Receiving device functions
byte_t *UDPgetpacketpointers(byte_t *pktbuf,struct ether_header **etherHeader, struct iphdr **IPheader,struct udphdr **UDPheader);
unsigned short UDPgetpayloadsize(struct udphdr *UDPheader);
bool validateEthCsum(byte_t *packet, csum16_t csum, csum16_t *combinedcsum, csumt_t type, void *args);

// Test functions, to inject errors inside packets - should never be used under normal circumstances
void test_injectIPCsumError(byte_t *IPpacket);
void test_injectUDPCsumError(byte_t *UDPpacket);

#endif