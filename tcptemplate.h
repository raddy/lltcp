#ifndef TCPTEMPLATE_H
#define TCPTEMPLATE_H



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

unsigned get_source_ip(struct TemplatePacket *tmpl);
unsigned get_dest_ip(struct TemplatePacket *tmpl);
unsigned get_source_port(struct TemplatePacket *tmpl);

#endif