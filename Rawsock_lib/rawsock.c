// Rawsock_lib, licensed under GPLv2
// 2018-01-02, version 0.1, supporting IP and UDP
#include "rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ipcsum_alth.h"

/**
	Fast UDP checksum calculation - 
	not an original work: coded by Andrea Righi in
	the Minirighi IA-32 Operating System,
	released under GNU GPL
	Definition at line 29 of file udp.c
**/
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
	const uint16_t *buf=buff;
	uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length=len;

	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if ( len & 1 )
		sum += *((uint8_t *)buf);

	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ( (uint16_t)(~sum)  );
}

/**
	Prepare a macaddr_t variable - 
	allocates a six element byte array
	to store any MAC address
**/
macaddr_t prepareMacAddrT() {
	macaddr_t mac;
	int i;

	mac=malloc(MAC_ADDR_SIZE*sizeof(unsigned char));

	for(i=0;i<MAC_ADDR_SIZE;i++) {
		mac[i]=0xFF;
	}

	return mac;
}

/**
	Free a macaddr_t variable - 
	frees a previously allocated array
**/
void freeMacAddrT(macaddr_t mac) {
	free(mac);
}

/**
	Get the MAC address type - 
	starting from a MAC address type
	its type is returned (unicast, multicast, broadcast)
**/
unsigned int macAddrTypeGet(macaddr_t mac) {
	if(mac!=NULL) {
		if(mac[0]==0x01) {
			return MAC_MULTICAST;
		} else if(mac[0]==0xFF && mac[1]==0xFF && mac[2]==0xFF && mac[3]==0xFF && mac[4]==0xFF && mac[5]==0xFF) {
			return MAC_BROADCAST;
		} else {
			return MAC_UNICAST;
		}
	} else {
		return MAC_NULL;
	}
}

/**
	wlanLookup - 
	automatically look for available WLAN interfaces.
	When only one interface is available and "0" is specified as index, 
	that interface name is returned inside "devname". 
	Then, if the other two arguments are not NULL, the interface index and 
	the corresponding source MAC address (if available) is returned.

	If more than one interface is present, the number of available interfaces 
	is returned by the function and the index is used to point to a specific interface 
	(for instance index=1 can be used to point to a possible "wlan1" interface).

	Return values: if ok: number of found interfaces
	ERR_WLAN_NOIF -> no interfaces found
	ERR_WLAN_SOCK -> cannot create socket to look for wireless interfaces
	ERR_WLAN_GETIFADDRS -> error in calling getifaddrs()
	ERR_WLAN_INDEX -> invalid index value
	ERR_WLAN_GETSRCMAC -> unable to get source MAC address (if requested)
	ERR_WLAN_GETIFINDEX -> unable to get source interface index (if requested)
**/
rawsockerr_t wlanLookup(char *devname, int *ifindex, macaddr_t mac, unsigned int index) {
	// Variables for wlan interfaces detection
	int sFd=-1;
	// struct ifaddrs used to look for available interfaces and bind to a wireless interface
	struct ifaddrs *ifaddr_head, *ifaddr_it;
	// struct ifreq to check whether an interface is wireless or not. The ifr_name field is used to specify which device to affect.
	struct ifreq wifireq;
	// Pointers to manage the list containing all valid wireless interfaces
	struct iflist *iflist_head=NULL; // Head
	struct iflist *curr_ptr=NULL; // Current element
	struct iflist *iflist_it=NULL; // To iterate the list
	struct iflist *iflist_u=NULL; // To free the list
	int ifno=0;
	int return_value=1; // Return value: >0 ok - # of found interfaces, <=0 error 
								 // (=0 for no WLAN interfaces, =-1 for socket error, =-2 for getifaddrs error)
							     // (=-3 for wrong index, =-4 unable to get MAC address, =-5 unable to get ifindex)

	// Linked list nodes to store the WLAN interfaces
	struct iflist {
		struct iflist *next;
		struct ifaddrs *ifaddr_ptr;
	};

	// Open socket (needed)
	sFd=socket(AF_INET,SOCK_DGRAM,0); // Any socket should be fine (to be better investigated!)
	if(sFd==-1) {
		return_value=-1;
		goto sock_error_occurred;
	}

	// Getting all interface addresses
	if(getifaddrs(&ifaddr_head)==-1) {
		return_value=-2;
		goto getifaddrs_error_occurred;
	}

	// Looking for wlan interfaces
	bzero(&wifireq,sizeof(wifireq));
	// Iterating over the interfaces linked list
	for(ifaddr_it=ifaddr_head;ifaddr_it!=NULL;ifaddr_it=ifaddr_it->ifa_next) {
		if(ifaddr_it->ifa_addr!=NULL && ifaddr_it->ifa_addr->sa_family == AF_PACKET) {
			// fprintf(stdout,"Checking interface %s for use.\n",ifaddr_it->ifa_name);
			// IFNAMSIZ is defined by system libraries and it "defines the maximum buffer size needed to hold an interface name, 
			//  including its terminating zero byte"
			// This is done because (from man7.org) "normally, the user specifies which device to affect by setting
            //  ifr_name to the name of the interface"
			strncpy(wifireq.ifr_name,ifaddr_it->ifa_name,IFNAMSIZ); 

			// Trying to get the Wireless Extensions (a socket descriptor must be specified to ioctl())
			if(ioctl(sFd,SIOCGIWNAME,&wifireq)!=-1) {
				// Check if the interface is up
				if(ioctl(sFd,SIOCGIFFLAGS,&wifireq)!=-1 && (wifireq.ifr_flags & IFF_UP)) {
					// If the interface is up, add it to the head of the "iflist" (it is not added to the tail in order to
					//  avoid defining an extra pointer)
					// fprintf(stdout,"Interface %s (#%d) is up. It may be used.\n",ifaddr_it->ifa_name,ifno);
					ifno++;
					curr_ptr=malloc(sizeof(struct iflist));
					curr_ptr->ifaddr_ptr=ifaddr_it;
					if(iflist_head==NULL) {
						iflist_head=curr_ptr;
						iflist_head->next=NULL;
					} else {
						curr_ptr->next=iflist_head;
						iflist_head=curr_ptr;
					}
				} // else {
					// fprintf(stdout,"Interface is not up (or it is impossibile to check that).\n");
				// }
			} // else {
				// fprintf(stdout,"Interface is not wireless.\n");
			// }
		}
	}

	// No wireless interfaces found (the list is empty)
	if(iflist_head==NULL) {
		// fprintf(stderr,"No wireless interfaces found. The program will terminate now.\n");
		return_value=0;
		goto error_occurred;
	} else if(ifno==1) {
		// Only one wireless interface found -> it is possible to ignore 'index'
		strncpy(devname,iflist_head->ifaddr_ptr->ifa_name,IFNAMSIZ);
		// fprintf(stdout,"Interface %s (#0) will be used.\n\n",devname);
	} else {
		// Multiple wireless interfaces found -> use the value of 'index'
		// fprintf(stdout,"Please insert the interface # to be used: ");
		// fflush(stdout);
		// fscanf(stdin,"%d",&ifindex);
		if(index>=ifno) {
			//fprintf(stderr,"Invalid interface index. Aborting execution.\n");
			return_value=-3;
			goto error_occurred;
		}
		return_value=ifno; // Return the number of interfaces found
		// Iterate the list until the chosen interface is reached
		iflist_it=iflist_head;
		while(index<=ifno-2) {
			iflist_it=iflist_it->next;
			index++;
		}
		strncpy(devname,iflist_it->ifaddr_ptr->ifa_name,IFNAMSIZ);
		// fprintf(stdout,"Interface %s will be used.\n\n",devname);
	}

	// Get MAC address of the interface (if requested by the user with a non-NULL mac)
	if(mac!=NULL) {
		strncpy(wifireq.ifr_name,devname,IFNAMSIZ); 
		if(ioctl(sFd,SIOCGIFHWADDR,&wifireq)!=-1) {
			memcpy(mac,wifireq.ifr_hwaddr.sa_data,MAC_ADDR_SIZE);
		} else {
			return_value=-4;
			goto error_occurred;
		}
	}

	// Get interface index of the interface (if requested by the user with a non-NULL ifindex)
	if(ifindex!=NULL) {
		strncpy(wifireq.ifr_name,devname,IFNAMSIZ);
		if(ioctl(sFd,SIOCGIFINDEX,&wifireq)!=-1) {
			*ifindex=wifireq.ifr_ifindex;
		} else {
			return_value=-5;
			goto error_occurred;
		}
	}

	error_occurred:
	// iflist and the other list are no more useful -> free them
	freeifaddrs(ifaddr_head);
	for(iflist_it=iflist_head;iflist_it!=NULL;iflist_it=iflist_u) {
		iflist_u=iflist_it->next;
		free(iflist_it);
	}

	getifaddrs_error_occurred:
	// Close socket
	close(sFd);

	sock_error_occurred:
	return return_value;
}

/**
	Print more detailed error messages - 
	given a stream (for ex. stdout or stderr) and
	the error name (see rawsock.h)
**/
void rs_printerror(FILE *stream,rawsockerr_t code) {
	switch(code) {
		case ERR_WLAN_NOIF:
			fprintf(stream,"wlanLookup: No WLAN interfaces found.\n");
		break;

		case ERR_WLAN_SOCK:
			fprintf(stream,"wlanLookup: socket creation error.\n");
		break;

		case ERR_WLAN_GETIFADDRS:
			fprintf(stream,"wlanLookup: getifaddrs() error.\n");
		break;

		case ERR_WLAN_INDEX:
			fprintf(stream,"wlanLookup: wrong index specified.\n");
		break;

		case ERR_WLAN_GETSRCMAC:
			fprintf(stream,"wlanLookup: unable to get source MAC address.\n");
		break;

		case ERR_WLAN_GETIFINDEX:
			fprintf(stream,"wlanLookup: unable to get interface index.\n");
		break;

		case ERR_IPHEADP_SOCK:
			fprintf(stream,"IP4headPopulateB: socket creation error.\n");
		break;

		case ERR_IPHEAD_NOSRCADDR:
			fprintf(stream,"IP4headPopulateB: unable to retrieve source IP address.\n");
		break;

		default:
			fprintf(stream,"Unknown error.\n");
	}
}

/**
	Display packet in hexadecimal form - 
	packet length is required
**/
void display_packet(const char *text,byte_t *packet,unsigned int len) {
	int i;

	fprintf(stdout,"%s -> ",text);
	for(i=0;i<len;i++) {
		fprintf(stdout,"%02x ",packet[i]);
	}
	fprintf(stdout,"\n");
	fflush(stdout);
}

/**
	Display packet in character form - 
	packet length is required
**/
void display_packetc(const char *text,byte_t *packet,unsigned int len) {
	int i;

	fprintf(stdout,"%s -> ",text);
	for(i=0;i<len;i++) {
		fprintf(stdout,"%c",packet[i]);
	}
	fprintf(stdout,"\n");
	fflush(stdout);
}

/**
	Populate broadcast Ethernet header -
	the user shall specify an already existing ether_header structure, the source MAC
	and the Ethertype (either one type in net/ethernet.h or one type in rawsock.h)
**/
void etherheadPopulateB(struct ether_header *etherHeader, macaddr_t mac, ethertype_t type) {
	unsigned char broadcastMAC[ETHER_ADDR_LEN]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	memcpy(etherHeader->ether_dhost,broadcastMAC,ETHER_ADDR_LEN);
	memcpy(etherHeader->ether_shost,mac,ETHER_ADDR_LEN);
	etherHeader->ether_type = htons(type);
}

/**
	Populate standard Ethernet header -
	the user shall specify an already existing ether_header structure, the source MAC
	the destination MAC and the Ethertype (either one type in net/ethernet.h or one type in rawsock.h)
**/
void etherheadPopulate(struct ether_header *etherHeader, macaddr_t macsrc, macaddr_t macdst, ethertype_t type) {
	memcpy(etherHeader->ether_dhost,macdst,ETHER_ADDR_LEN);
	memcpy(etherHeader->ether_shost,macsrc,ETHER_ADDR_LEN);
	etherHeader->ether_type = htons(type);
}

/**
	Combine Ethernet SDU and PCI -
	the user shall specify a buffer in which the full packet will be put, the ethernet header, the SDU
	(byte_t *sdu) and its size in bytes
**/
size_t etherEncapsulate(byte_t *packet,struct ether_header *header,byte_t *sdu,size_t sdusize) {
	size_t packetsize=sizeof(struct ether_header)+sdusize;

	memcpy(packet,header,sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header),sdu,packetsize);

	return packetsize;
}

/**
	Populate standard IP version 4 header -
	the user shall specify an already existing IP header structure, the interface name (for instance "wlan0"), 
	the destination IP address, the TOS value, the fragment offset value, the TTL, the protocol, the flags (reserved, DF, MF).
	The function, other than returning possible errors (ERR_IPHEADP_SOCK or ERR_IPHEAD_NOSRCADDR), returns a structure
	containing the source and destination IP addresses, if struct ipaddrs *addrs is not NULL.
**/
rawsockerr_t IP4headPopulate(struct iphdr *IPhead, char *devname, char *destIP, unsigned char tos,unsigned short frag_offset, unsigned char ttl, unsigned char protocol,unsigned int flags,struct ipaddrs *addrs) {
	struct in_addr destIPAddr;
	int sFd; // To get the current IP address
	struct ifreq wifireq;

	IPhead->ihl=BASIC_IHL;
	IPhead->version=IPV4;
	IPhead->tos=(__u8) tos;
	IPhead->frag_off=htons(frag_offset);
	IPhead->frag_off=(IPhead->frag_off) | flags;
	IPhead->ttl=(__u8) ttl;
	IPhead->protocol=(__u8) protocol;
	inet_pton(AF_INET,destIP,(struct in_addr *)&destIPAddr);
	IPhead->daddr=destIPAddr.s_addr;

	// Get own IP address
	sFd=socket(AF_INET,SOCK_DGRAM,0);
	if(sFd==-1) {
		return -10;
	}
	strncpy(wifireq.ifr_name,devname,IFNAMSIZ);
	wifireq.ifr_addr.sa_family = AF_INET;
	if(ioctl(sFd,SIOCGIFADDR,&wifireq)!=0) {
		close(sFd);
		return -11;
	}
	close(sFd);
	IPhead->saddr=((struct sockaddr_in*)&wifireq.ifr_addr)->sin_addr.s_addr;
	if(addrs!=NULL) {
		addrs->src=IPhead->saddr;
		addrs->dst=IPhead->daddr;
	}

	// Initialize checksum to 0
	IPhead->check=0;

	return 0;
}

/**
	Populate broadcast IP version 4 header -
	the user shall specify an already existing IP header structure, the interface name (for instance "wlan0"),
	the TOS value, the fragment offset value, the TTL, the protocol, the flags (reserved, DF, MF).
	The function, other than returning possible errors (ERR_IPHEADP_SOCK or ERR_IPHEAD_NOSRCADDR), returns a structure
	containing the source and destination IP addresses, if struct ipaddrs *addrs is not NULL.
**/
rawsockerr_t IP4headPopulateB(struct iphdr *IPhead, char *devname,unsigned char tos,unsigned short frag_offset, unsigned char ttl, unsigned char protocol,unsigned int flags,struct ipaddrs *addrs) {
	struct in_addr broadIPAddr;
	int sFd; // To get the current IP address
	struct ifreq wifireq;

	IPhead->ihl=BASIC_IHL;
	IPhead->version=IPV4;
	IPhead->tos=(__u8) tos;
	IPhead->frag_off=htons(frag_offset);
	IPhead->frag_off=(IPhead->frag_off) | flags;
	IPhead->ttl=(__u8) ttl;
	IPhead->protocol=(__u8) protocol;
	inet_pton(AF_INET,"255.255.255.255",(struct in_addr *)&broadIPAddr);
	IPhead->daddr=broadIPAddr.s_addr;

	// Get own IP address
	sFd=socket(AF_INET,SOCK_DGRAM,0);
	if(sFd==-1) {
		return -10;
	}
	strncpy(wifireq.ifr_name,devname,IFNAMSIZ);
	wifireq.ifr_addr.sa_family = AF_INET;
	if(ioctl(sFd,SIOCGIFADDR,&wifireq)!=0) {
		close(sFd);
		return -11;
	}
	close(sFd);
	IPhead->saddr=((struct sockaddr_in*)&wifireq.ifr_addr)->sin_addr.s_addr;
	if(addrs!=NULL) {
		addrs->src=IPhead->saddr;
		addrs->dst=IPhead->daddr;
	}

	// Initialize checksum to 0
	IPhead->check=0;

	return 0;
}

/**
	Add ID to a given (by the caller) IPv4 header
**/
void IP4headAddID(struct iphdr *IPhead, unsigned short id) {
	IPhead->id=htons(id);
}

/**
	Add Total Length to a given (by the caller) IPv4 header
**/
void IP4headAddTotLen(struct iphdr *IPhead, unsigned short len) {
	IPhead->tot_len=htons(len);
}

/**
	Combine IPv4 SDU and PCI -
	the user shall specify a buffer in which the full packet will be put, the ethernet header, the SDU
	(byte_t *sdu) and its size in bytes
**/
size_t IP4Encapsulate(byte_t *packet,struct iphdr *header,byte_t *sdu,size_t sdusize) {
	size_t packetsize=sizeof(struct iphdr)+sdusize;

	header->tot_len=htons(packetsize);
	header->check=0; // Reset to 0 in case of subsequent calls

	header->check=ip_fast_csum((__u8 *)header, BASIC_IHL);

	memcpy(packet,header,sizeof(struct iphdr));
	memcpy(packet+sizeof(struct iphdr),sdu,packetsize);

	return packetsize;
}

/**
	Populate standard UDP 4 header -
	the user shall specify an already existing UDP header structure, the source port
	and the destination port
**/
void UDPheadPopulate(struct udphdr *UDPhead, unsigned short sourceport, unsigned short destport) {
	UDPhead->source=htons(sourceport);
	UDPhead->dest=htons(destport);

	// Initialize checksum to 0
	UDPhead->check=0;
}

/**
	Combine UDP payload and header -
	the user shall specify a buffer in which the full packet will be put, the UDP header, the payload
	(byte_t *payload), its size in bytes and a structure (see the definition in rawsock.h) containing
	source and destion IP addresses, which are used to compute the checksum
**/
size_t UDPencapsulate(byte_t *packet,struct udphdr *header,char *data,size_t payloadsize,struct ipaddrs addrs) {
	size_t packetsize=sizeof(struct udphdr)+payloadsize;

	header->len=htons(packetsize);
	header->check=0; // Reset to 0 in case of subsequent calls

	memcpy(packet,header,sizeof(struct udphdr));
	memcpy(packet+sizeof(struct udphdr),data,packetsize);

	header->check=udp_checksum(packet,packetsize,addrs.src,addrs.dst);

	memcpy(packet,header,sizeof(struct udphdr));

	return packetsize;
}

/**
	Get pointers to headers and payload in UDP packet buffer -
	obtain, given a certain buffer containing an UDP packet, the pointer to the headers 
	and payload sections
	Example of call: payload=UDPgetpacketpointers(packet,&etherHeader,&IPheader,&udpHeader);
	with:
	struct ether_header* etherHeader;
	struct iphdr *IPheader;
	struct udphdr *udpHeader;
	byte_t *payload;
	--------------------------------
	packet is specified by the user, 
	payload is returned by the function (requires an already allocated array!)
	the ethernet header pointer is written by this function, as the IP and UDP header pointers
**/
byte_t *UDPgetpacketpointers(byte_t *pktbuf,struct ether_header **etherHeader, struct iphdr **IPheader,struct udphdr **UDPheader) {
	byte_t *payload;

	*etherHeader=(struct ether_header*) pktbuf;
	*IPheader=(struct iphdr*)(pktbuf+sizeof(struct ether_header));
	*UDPheader=(struct udphdr*)(pktbuf+sizeof(struct ether_header)+sizeof(struct iphdr));
	payload=(pktbuf+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr));

	return payload;
}

/**
	Get UDP payload size as unsigned short (int), given a UDP header pointer
**/
unsigned short UDPgetpayloadsize(struct udphdr *UDPheader) {
	return (ntohs(UDPheader->len)-UDPHEADERLEN);
}

/**
	Validate the checksum of a raw 'Ethernet' packet i.e.
	of any packet containing a struct ether_header as first bytes -
	Arguments:
	. byte_t *packet -> pointer to the full packet buffer
	. csum16_t csum -> checksum value to be checked against the newly computed value, from 'packet'
	. csum16_t *combinedcsum -> should be NULL for non combined checksum types, otherwise it should contain
	the value of the second checksum to be checked (the oredring between csum and *combinedcsum is the same
	as the one in the checksum type constant - for instance: CSUM_UDPIP requires csum<-UDP and *combinedcsum<-IP)
	If NULL is specified for any combined type, the function will always return 'false'.
	. csumt_t type -> checksum protocol: various protocols can be specified within the same function, in order to keep
	it easier to extend as newer protocols will be implemented inside the library.
	The supported protocols are defined inside proper "Checksum protocols" constants in rawsock.h.
	Both simple protocols and combined ones are supported: in the first case, only the checksum related to the
	specified protocol is checked (csum16_t csum), in the second case, two checksums, contained inside the same
	packet, are checked (csum16_t csum and csum16_t *combinedcsum) -> this can be useful, for instance, to
	check both the UDP and IP checksums all at once; in case a combined mode is selected 'combinedcsum' shall
	be non-NULL, otherwise the function will always return 'false'.
	. void *args -> additional arguments: these are typically dependant on the specified protocol: for instance,
	using IP, they are not needed and NULL can be passed; instead, when using UDP (or UDP+IP), they shall contain
	the pointer to a single value which is the payload length (this may avoid computing it multiple times, outside 
	and inside this function, when a variable containing it is already available)
**/
bool validateEthCsum(byte_t *packet, csum16_t csum, csum16_t *combinedcsum, csumt_t type, void *args) {
	csum16_t currCsum;
	bool returnVal=false;
	void *headerPtr; // Generic header pointer
	void *payloadPtr; // Generic payload/SDU pointer
	size_t packetsize; // Used in UDP checksum calculation
	__sum16 storedCsum; // To store the current value of checksum, read from 'packet'

	// Directly return 'false' (as an error occurred) if a combined type is specified but combinedcsum is NULL
	if(type>=0x80 && combinedcsum==NULL) {
		return false;
	}

	// Discriminate the different protocols
	switch(type) {
		case CSUM_IP:
			headerPtr=(struct iphdr*)(packet+sizeof(struct ether_header));

			// Checksum should start with a value of 0x0000 in order to be correctly computed:
			//  set it to 0 and restore it, to avoid making a copy of the packet in memory
			storedCsum=((struct iphdr *) headerPtr)->check;
			((struct iphdr *) headerPtr)->check=0;

			currCsum=ip_fast_csum((__u8 *)headerPtr, ((struct iphdr *) headerPtr)->ihl);

			((struct iphdr *) headerPtr)->check=storedCsum;

			returnVal=(currCsum==csum);
		break;
		case CSUM_UDP:
		case CSUM_UDPIP:
			// payloadsize should be specified, otherwise 'false' will be always returneds
			if(args==NULL) {
				returnVal=false;
			} else {
				// Get packetsize
				packetsize=sizeof(struct udphdr)+*((size_t *) args);

				headerPtr=(struct iphdr*)(packet+sizeof(struct ether_header));
				payloadPtr=(struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));

				storedCsum=((struct udphdr *) payloadPtr)->check;
				((struct udphdr *) payloadPtr)->check=0;

				currCsum=udp_checksum(payloadPtr,packetsize,((struct iphdr *)headerPtr)->saddr,((struct iphdr *)headerPtr)->daddr);

				((struct udphdr *) payloadPtr)->check=storedCsum;

				returnVal=(currCsum==csum);

				if(type==CSUM_UDPIP) {
					if(combinedcsum==NULL) {
						returnVal=false;
					} else {
						// Compute IP checksum
						storedCsum=((struct iphdr *) headerPtr)->check;
						((struct iphdr *) headerPtr)->check=0;

						currCsum=ip_fast_csum((__u8 *)headerPtr, ((struct iphdr *)headerPtr)->ihl);

						((struct iphdr *) headerPtr)->check=storedCsum;

						returnVal=returnVal && (currCsum==(*combinedcsum));
					}
				}
			}
		break;
		default:
			returnVal=false;
	}

	return returnVal;
}

/**
	Test function: inject a checksum error in an IP packet -
	The pointer to the full IP packet shall be passed (IP header+payload)
**/
void test_injectIPCsumError(byte_t *IPpacket) {
	// Get header pointer
	struct iphdr *IPheader=(struct iphdr *) IPpacket;

	if(IPpacket!=NULL) {
		// Change checksum, avoiding possible overflow situations
		if(IPheader->check!=0xFF) {
			IPheader->check=IPheader->check+1;
		} else {
			IPheader->check=0x00;
		}
	}
}

/**
	Test function: inject a checksum error in an UDP packet -
	The pointer to the full UDP packet shall be passed (UDP header+payload)
**/
void test_injectUDPCsumError(byte_t *UDPpacket) {
	// Get header pointer
	struct udphdr *UDPheader=(struct udphdr *) UDPpacket;

	if(UDPheader!=NULL) {
		// Change checksum, avoiding possible overflow situations
		if(UDPheader->check!=0xFF) {
			UDPheader->check=UDPheader->check+1;
		} else {
			UDPheader->check=0x00;
		}
	}
}