#ifndef USERTCP_H
#define USERTCP_H

#define EQUALS(lhs,rhs) (memcmp((lhs),(rhs),12)==0)

struct TCP_Control_Block;
struct TemplatePacket;
struct TCP_ConnectionTable;

struct TCP_ConnectionTable * 
tcpcon_create_table( size_t entry_count,unsigned timeout);

void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon);



/**
 * Lookup a connection record based on IP/ports.
 */
struct TCP_Control_Block *
tcpcon_lookup_tcb(
    struct TCP_ConnectionTable *tcpcon, 
    unsigned ip_src, unsigned ip_dst,
    unsigned port_src, unsigned port_dst);

/**
 * Create a new TCB (TCP control block)
 */
struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon, 
    unsigned ip_src, unsigned ip_dst,
    unsigned port_src, unsigned port_dst,
    unsigned my_seqno, unsigned their_seqno);

#endif