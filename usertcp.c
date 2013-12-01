#include "usertcp.h"

struct TCP_Control_Block
{

    unsigned ip_me;
    unsigned ip_them;

    unsigned short port_me;
    unsigned short port_them;

    uint32_t seqno_me;      /* next seqno I will use for transmit */
    uint32_t seqno_them;    /* the next seqno I expect to receive */
    uint32_t ackno_me;
    uint32_t ackno_them;

    struct TCP_Control_Block *next;
    struct TimeoutEntry timeout[1];
    
    unsigned tcpstate:4;

    unsigned short payload_length;
    time_t when_created;
    const unsigned char *payload;

};

struct TCP_ConnectionTable {
    struct TCP_Control_Block **entries;
    struct TCP_Control_Block *freed_list;
    unsigned count;
    unsigned mask;
    unsigned timeout;

    uint64_t active_count;

    struct Timeouts *timeouts;
    struct TemplatePacket *pkt_template;
};

enum {
    STATE_SYN_SENT,
    STATE_READY_TO_SEND,
    STATE_PAYLOAD_SENT,
    STATE_WAITING_FOR_RESPONSE,
};


struct TCP_ConnectionTable * 
tcpcon_create_table( size_t entry_count,unsigned timeout){
    struct TCP_ConnectionTable *tcpcon;

    tcpcon = (struct TCP_ConnectionTable *)malloc(sizeof(*tcpcon));
    if (tcpcon == NULL)
        exit(1);
    memset(tcpcon, 0, sizeof(*tcpcon));
    tcpcon->timeout = timeout;
    if (tcpcon->timeout == 0)
        tcpcon->timeout = 30; /* half a minute before destroying tcb */

    /* Find nearest power of 2 to the tcb count, but don't go
     * over the number 16-million */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entry_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1<<24);
                break;
            }
        }
        if (new_entry_count > (1<<24))
            new_entry_count = (1<<24);
        if (new_entry_count < (1<<10))
            new_entry_count = (1<<10);
        entry_count = new_entry_count;
    }

    /* Create the table. If we can't allocate enough memory, then shrink
     * the desired size of the table */
    while (tcpcon->entries == 0) {
        tcpcon->entries = (struct TCP_Control_Block**)
                            malloc(entry_count * sizeof(*tcpcon->entries));
        if (tcpcon->entries == NULL) {
            entry_count >>= 1;
        }
    }
    memset(tcpcon->entries, 0, entry_count * sizeof(*tcpcon->entries));

    tcpcon->count = (unsigned)entry_count;
    tcpcon->mask = (unsigned)(entry_count-1);

    //tcpcon->timeouts = timeouts_create(TICKS_FROM_SECS(time(0)));
    tcpcon->pkt_template = pkt_template;

    return tcpcon;
}

void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon)
{
    unsigned i;
    
    if (tcpcon == NULL)
        return;
    
    /*
     * Do a graceful destruction of all the entires. If they have banners,
     * they will be sent to the output
     */
    for (i=0; i<=tcpcon->mask; i++) {
        while (tcpcon->entries[i])
            tcpcon_destroy_tcb(tcpcon, tcpcon->entries[i]);
    }
    
    /*
     * Now free the memory
     */
    while (tcpcon->freed_list) {
        struct TCP_Control_Block *tcb = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
        free(tcb);
    }
    
    free(tcpcon->entries);
    free(tcpcon);
}

struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon, 
    unsigned ip_me, unsigned ip_them,
    unsigned port_me, unsigned port_them,
    unsigned seqno_me, unsigned seqno_them)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = tcb_hash(ip_me, port_me, ip_them, port_them);
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }
    if (tcb == NULL) {
        if (tcpcon->freed_list) {
            tcb = tcpcon->freed_list;
            tcpcon->freed_list = tcb->next;
        } else {
            tcb = (struct TCP_Control_Block*)malloc(sizeof(*tcb));
            if (tcb == NULL) {
                fprintf(stderr, "tcb: out of memory\n");
                exit(1);
            }
        }
        memset(tcb, 0, sizeof(*tcb));
        tcb->next = tcpcon->entries[index & tcpcon->mask];
        tcpcon->entries[index & tcpcon->mask] = tcb;
        memcpy(tcb, &tmp, 12);
        tcb->seqno_me = seqno_me;
        tcb->seqno_them = seqno_them;
        tcb->ackno_me = seqno_them;
        tcb->ackno_them = seqno_me;
        tcb->when_created = global_now;
        tcb->banner1_state.port = tmp.port_them;

        timeout_init(tcb->timeout);
        

        tcpcon->active_count++;
        global_tcb_count = tcpcon->active_count;
    }

    return tcb;
}


