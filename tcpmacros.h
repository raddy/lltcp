/* TCP HANDLING MACROS*/
#ifndef TCPMACROS_H
#define TCPMACROS_H

#define TCP_SEQNO(px,i) (px[i+4]<<24|px[i+5]<<16|px[i+6]<<8|px[i+7])
#define TCP_ACKNO(px,i) (px[i+8]<<24|px[i+9]<<16|px[i+10]<<8|px[i+11])
#define TCP_FLAGS(px,i) (px[(i)+13])
#define TCP_IS_SYNACK(px,i) ((TCP_FLAGS(px,i) & 0x12) == 0x12)
#define TCP_IS_ACK(px,i) ((TCP_FLAGS(px,i) & 0x10) == 0x10)
#define TCP_IS_RST(px,i) ((TCP_FLAGS(px,i) & 0x4) == 0x4)
#define TCP_IS_FIN(px,i) ((TCP_FLAGS(px,i) & 0x1) == 0x1)

#endif