#include "tcptemplate.h"
#include "checksums.h"


/***************************************************************************
 * Checksum the IP header. This is a "partial" checksum, so we
 * don't reverse the bits ~.
 ***************************************************************************/
unsigned
ip_header_checksum(const unsigned char *px, unsigned offset, unsigned max_offset)
{
    unsigned header_length = (px[offset]>>2)&0xFC;
    unsigned xsum = 0;
    unsigned i;

    /* restrict check only over packet */
    if (max_offset > offset + header_length)
        max_offset = offset + header_length;
    
    /* add all the two-byte words together */
    xsum = 0;
    for (i = offset; i < max_offset; i += 2) {
        xsum += px[i]<<8 | px[i+1];
    }

    /* if more than 16 bits in result, reduce to 16 bits */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_checksum2(const unsigned char *px, unsigned offset_ip,
              unsigned offset_tcp, size_t tcp_length)
{
    uint64_t xsum = 0;
    unsigned i;
    
    /* pseudo checksum */
    xsum = 6;
    xsum += tcp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];
    
    /* tcp checksum */
    for (i=0; i<tcp_length; i += 2) {
        xsum += px[offset_tcp + i]<<8 | px[offset_tcp + i + 1];
    }
    
    xsum -= (tcp_length & 1) * px[offset_tcp + i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    
    return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
/***************************************************************************
 ***************************************************************************/
unsigned
tcp_checksum(struct TemplatePacket *tmpl)
{
    const unsigned char *px = tmpl->packet;
    unsigned xsum = 0;
    unsigned i;
    
    /* pseudo checksum */
    xsum = 6;
    xsum += tmpl->offset_app - tmpl->offset_tcp;
    xsum += px[tmpl->offset_ip + 12] << 8 | px[tmpl->offset_ip + 13];
    xsum += px[tmpl->offset_ip + 14] << 8 | px[tmpl->offset_ip + 15];
    xsum += px[tmpl->offset_ip + 16] << 8 | px[tmpl->offset_ip + 17];
    xsum += px[tmpl->offset_ip + 18] << 8 | px[tmpl->offset_ip + 19];
    
    /* tcp checksum */
    for (i=tmpl->offset_tcp; i<tmpl->offset_app; i += 2) {
        xsum += tmpl->packet[i]<<8 | tmpl->packet[i+1];
    }
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    
    return xsum;
}
