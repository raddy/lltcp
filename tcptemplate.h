#ifndef TCPTEMPLATE_H
#define TCPTEMPLATE_H

#include <stdlib.h>


struct TemplatePacket {
    unsigned length;
    unsigned offset_ip;
    unsigned offset_tcp;
    unsigned offset_app;
    unsigned char *packet;
    unsigned checksum_ip;
    unsigned checksum_tcp;
    unsigned ip_id;
};

void template_init(struct TemplatePacket *tmpl,
	const unsigned char *mac_source,
    const unsigned char *mac_dest);

void template_target(struct TemplatePacket *tmpl, 
    unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    unsigned seqno);

size_t create_packet(struct TemplatePacket *tmpl, 
    unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    unsigned seqno,unsigned ackno,
    unsigned flags,const unsigned char *payload, 
    size_t payload_length,unsigned char *px, 
    size_t px_length);

unsigned get_source_ip(struct TemplatePacket *tmpl);
unsigned get_dest_ip(struct TemplatePacket *tmpl);
unsigned get_source_port(struct TemplatePacket *tmpl);
unsigned char * get_ip_checksum(struct TemplatePacket *tmpl);

#endif