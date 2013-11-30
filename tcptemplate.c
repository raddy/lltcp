#include "tcptemplate.h"
#include "preprocess.h"
#include "checksums.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned char default_tcp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x28"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x06"      /* TTL=255, proto=TCP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\0\0"          /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* sequence number */
    "\0\0\0\0"      /* ack number */
    "\x50"          /* header length */
    "\x02"          /* SYN */
    "\x0\x0"        /* window */
    "\xFF\xFF"      /* checksum */
    "\x00\x00"      /* urgent pointer */
;

unsigned get_dest_ip(struct TemplatePacket *tmpl){

    return tmpl->packet[tmpl->offset_ip+16]<<24 | tmpl->packet[tmpl->offset_ip+17]<<16
        | tmpl->packet[tmpl->offset_ip+18]<<8 | tmpl->packet[tmpl->offset_ip+19]<<0;
}

unsigned get_source_ip(struct TemplatePacket *tmpl){

    return tmpl->packet[tmpl->offset_ip+12]<<24 | tmpl->packet[tmpl->offset_ip+13]<<16
        | tmpl->packet[tmpl->offset_ip+14]<<8 | tmpl->packet[tmpl->offset_ip+15]<<0;
}

unsigned get_source_port(struct TemplatePacket *tmpl){

    return tmpl->packet[tmpl->offset_ip+0]<<8 | tmpl->packet[tmpl->offset_ip+1]<<0;
}


void template_target(struct TemplatePacket *tmpl, unsigned ip_them, 
	unsigned port_them, unsigned ip_me, unsigned port_me,
    unsigned seqno){

	unsigned ip_id;
	uint64_t xsum;


	ip_id = ip_them ^ port_them ^ seqno; //XOR
	{
        unsigned total_length = tmpl->length - tmpl->offset_ip;
        tmpl->packet[tmpl->offset_ip+2] = (unsigned char)(total_length>>8);
        tmpl->packet[tmpl->offset_ip+3] = (unsigned char)(total_length>>0);
    }

    tmpl->packet[tmpl->offset_ip+4] = (unsigned char)(ip_id >> 8);
    tmpl->packet[tmpl->offset_ip+5] = (unsigned char)(ip_id & 0xFF);
    tmpl->packet[tmpl->offset_ip+12] = (unsigned char)((ip_me >> 24) & 0xFF);
    tmpl->packet[tmpl->offset_ip+13] = (unsigned char)((ip_me >> 16) & 0xFF);
    tmpl->packet[tmpl->offset_ip+14] = (unsigned char)((ip_me >>  8) & 0xFF);
    tmpl->packet[tmpl->offset_ip+15] = (unsigned char)((ip_me >>  0) & 0xFF);
    tmpl->packet[tmpl->offset_ip+16] = (unsigned char)((ip_them >> 24) & 0xFF);
    tmpl->packet[tmpl->offset_ip+17] = (unsigned char)((ip_them >> 16) & 0xFF);
    tmpl->packet[tmpl->offset_ip+18] = (unsigned char)((ip_them >>  8) & 0xFF);
    tmpl->packet[tmpl->offset_ip+19] = (unsigned char)((ip_them >>  0) & 0xFF);


    xsum = tmpl->checksum_ip;
    xsum += tmpl->length - tmpl->offset_app;
    xsum += (ip_id&0xFFFF);
    xsum += ip_them;
    xsum += ip_me;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    tmpl->packet[tmpl->offset_ip+10] = (unsigned char)(xsum >> 8);
    tmpl->packet[tmpl->offset_ip+11] = (unsigned char)(xsum & 0xFF);

    xsum = 0;

    tmpl->packet[tmpl->offset_tcp+ 0] = (unsigned char)(port_me >> 8);
    tmpl->packet[tmpl->offset_tcp+ 1] = (unsigned char)(port_me & 0xFF);
    tmpl->packet[tmpl->offset_tcp+ 2] = (unsigned char)(port_them >> 8);
    tmpl->packet[tmpl->offset_tcp+ 3] = (unsigned char)(port_them & 0xFF);
    tmpl->packet[tmpl->offset_tcp+ 4] = (unsigned char)(seqno >> 24);
    tmpl->packet[tmpl->offset_tcp+ 5] = (unsigned char)(seqno >> 16);
    tmpl->packet[tmpl->offset_tcp+ 6] = (unsigned char)(seqno >>  8);
    tmpl->packet[tmpl->offset_tcp+ 7] = (unsigned char)(seqno >>  0);

    xsum += (uint64_t)tmpl->checksum_tcp
            + (uint64_t)ip_me
            + (uint64_t)ip_them
            + (uint64_t)port_me
            + (uint64_t)port_them
            + (uint64_t)seqno;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    tmpl->packet[tmpl->offset_tcp+16] = (unsigned char)(xsum >>  8);
    tmpl->packet[tmpl->offset_tcp+17] = (unsigned char)(xsum >>  0);

}


/*************************************
We initiatlize the raw foundation TCP packet by filling in both
the source and router mac addresses. We do some other nonsense
that probably we will just overwrite anyways -- not on CP regardless.
**************************************/
void template_init(struct TemplatePacket *tmpl,
	const unsigned char *mac_source,
    const unsigned char *mac_dest){

	unsigned packet_len = (unsigned)(sizeof(default_tcp_template)-1);
	unsigned char *px ;
	unsigned x;
	struct PreprocessedInfo parsed;

	memset(tmpl, 0, sizeof(*tmpl));

    tmpl->length = (unsigned)packet_len;
	tmpl->packet = (unsigned char *)malloc(2048);
	if (tmpl->packet == NULL)
        exit(1);
    memcpy(tmpl->packet, default_tcp_template, tmpl->length);
    px = tmpl->packet;

    x = preprocess_frame(px, tmpl->length, 1 /*enet*/, &parsed);
    if (!x || parsed.found == FOUND_NOTHING) {
    	printf("BAD TCP TEMPLATE");
        exit(1);
    }
    tmpl->offset_ip = parsed.ip_offset;
    tmpl->offset_tcp = parsed.transport_offset;

	memcpy(px+0, mac_dest, 6);
    memcpy(px+6, mac_source, 6);
    ((unsigned char*)parsed.ip_src)[0] = (unsigned char)(0>>24);
    ((unsigned char*)parsed.ip_src)[1] = (unsigned char)(0>>16);
    ((unsigned char*)parsed.ip_src)[2] = (unsigned char)(0>> 8);
    ((unsigned char*)parsed.ip_src)[3] = (unsigned char)(0>> 0);
    ((unsigned char*)parsed.ip_dst)[0] = (unsigned char)(0>>24);
    ((unsigned char*)parsed.ip_dst)[1] = (unsigned char)(0>>16);
    ((unsigned char*)parsed.ip_dst)[2] = (unsigned char)(0>> 8);
    ((unsigned char*)parsed.ip_dst)[3] = (unsigned char)(0>> 0);

    memset(px + tmpl->offset_ip + 4, 0, 2);  /* IP ID field */
    memset(px + tmpl->offset_ip + 10, 0, 2); /* checksum */
    memset(px + tmpl->offset_ip + 12, 0, 8); /* addresses */
    tmpl->checksum_ip = ip_header_checksum( tmpl->packet, 
                                            tmpl->offset_ip, 
                                            tmpl->length);
    memset(px + tmpl->offset_tcp + 0, 0, 8); /* destination port and seqno */
    memset(px + tmpl->offset_tcp + 16, 0, 2); /* checksum */
    tmpl->checksum_tcp = tcp_checksum(tmpl);

}