#include "rawsock.h"
#include "tcpmacros.h"
#include "prettyprint.h"
#include "preprocess.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

void raw_send(int raw,unsigned char * packet){

	if (write(raw, packet, 60)< 0)  {
		perror("write");
		exit(1);
	}
}

unsigned parse_raw(u_char * packet,int pkt_len){
	struct ip *ip;
	struct tcphdr *tcp;
	u_char *ptr;
	int l1_len = 14; //uh?
	int s_seq;
	struct PreprocessedInfo parsed;
	unsigned ip_me;
    unsigned port_me;
    unsigned ip_them;
    unsigned port_them;
    unsigned seqno_me;
    unsigned seqno_them;
    char buf[64];

	int x = preprocess_frame(packet, pkt_len, 1, &parsed);
	if (!x){
		printf("Corrupt Packet \n");
		return -1;
	}
	ip_me = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
    ip_them = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
    port_me = parsed.port_dst;
    port_them = parsed.port_src;



    seqno_them = TCP_SEQNO(packet, parsed.transport_offset);
    seqno_me = TCP_ACKNO(packet, parsed.transport_offset);
    if (parsed.found != FOUND_TCP)
    	return;

    /*printf("My IP: %u.%u.%u.%u :: ", 
            (ip_me>>24)&0xFF, (ip_me>>16)&0xFF, (ip_me>>8)&0xFF, (ip_me>>0)&0xFF);
   	printf("Their IP: %u.%u.%u.%u :: ", 
            (ip_them>>24)&0xFF, (ip_them>>16)&0xFF, (ip_them>>8)&0xFF, (ip_them>>0)&0xFF);
    printf("My Port: %u  Their Port: %u\n",port_me,port_them);

	printf("TCP ackno=0x%08x :: ",seqno_me);
	printf("TCP flags=0x%02x(%s)",TCP_FLAGS(packet, parsed.transport_offset),
		reason_string(TCP_FLAGS(packet, parsed.transport_offset), buf, sizeof(buf)));
	// flags=0x%02x(%s)\n",seqno_me, 
      //          */
	if (TCP_IS_SYNACK(packet, parsed.transport_offset)){
		printf("\nThis is a SYN-ACK!\n");
		return seqno_them;
		//we should create new tcp connection here
		//for now lets just
	}
	return 0;
}

ssize_t read_socket(int raw, char *packet_buffer){
    struct sockaddr_ll packet_info;
    int packet_info_size = sizeof(packet_info_size);
    
    ssize_t len;
    while (1){
		if((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1){
	            return -1;
	    }else{
	    	return len;
	    }
	}
}

int get_raw_socket(char * device, int protocol){//,struct sockaddr_ll *ps_sockaddr){
    int rawsock;
    struct sockaddr_ll sll;
    struct ifreq ifr;
 
    if((rawsock = socket(AF_PACKET, SOCK_RAW, htons(protocol)))== -1)
    {
        /* probably a premissions error */
        return -1;
    }
 
    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));
     
    /* get interface index  */
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
    {
        return -1;  /* device not found */
    }
 
    /* Bind our raw socket to this interface */
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol); 
    sll.sll_halen = ETH_ALEN;
    if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
    {
    	perror("Failed to bind socket.\n");
        return -1;  /* bind error */
    }

    //ps_sockaddr = &sll;
    //ps_sockaddr->sll_pkttype = PACKET_OUTGOING;
    return rawsock;
}

int rawsock_get_adapter_mac(const char *ifname, unsigned char *mac){
    int fd;
    int x;
    struct ifreq ifr;


    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0){
        perror("socket");
        goto end;
    }

    strcpy(ifr.ifr_name, ifname);
    x = ioctl(fd, SIOCGIFHWADDR, (char *)&ifr);
    if (x < 0) {
        perror("ioctl");
        goto end;
    }
    memcpy(mac, (unsigned char *)ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
end:
    close(fd);
    return 0;
}

unsigned rawsock_get_adapter_ip(const char *ifname) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    int x;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, ifname);

    x = ioctl(fd, SIOCGIFADDR, &ifr);
    if (x < 0) {
        fprintf(stderr, "ERROR:'%s': %s\n", ifname, strerror(errno));
        //fprintf(stderr, "ERROR:'%s': couldn't discover IP address of network interface\n", ifname);
        close(fd);
        return 0;
    }

    close(fd);

    sa = &ifr.ifr_addr;
    sin = (struct sockaddr_in *)sa;
    return ntohl(sin->sin_addr.s_addr);
}