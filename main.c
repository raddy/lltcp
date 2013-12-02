#include <stdio.h>
#include <stdlib.h>
#include <linux/if_ether.h>

#include "preprocess.h"
#include "tcpmacros.h"
#include "tcptemplate.h"
#include "rawsock.h"


//iptables -A INPUT -p tcp -i eth10gb1 --dport 7771 -j DROP
int main(int argc, char **argv)
{
	char *dev = "eth10gb1";
	char *targ_ip = "10.180.53.102";
	unsigned adapter_ip = rawsock_get_adapter_ip(dev);
	unsigned target_ip = ip_to_int(targ_ip);
	unsigned char adapter_mac[6];
	unsigned char router_mac[6] = {0x00, 0x1c, 0x73, 0x3f, 0xf5, 0x91};
	struct TemplatePacket tmpl[1];
	char packet_buffer[2048];
    ssize_t sock_len;
    size_t reponse_len;
    unsigned char response[60];

	rawsock_get_adapter_mac(dev, adapter_mac);
    
    
	template_init(tmpl,adapter_mac,router_mac);
	template_target(tmpl,target_ip,30333,adapter_ip,7771,0);
    int raw = get_raw_socket(dev,ETH_P_ALL);
    if (raw==-1){
        printf("Could not open raw socket!\n");
        exit(-1);
    }

    raw_send(raw,tmpl->packet);
    sock_len = read_socket(raw,packet_buffer); //grabs 1 packet
    parse_raw((u_char *)packet_buffer,(int)sock_len);
    response_len = create_packet(tmpl,target_ip,30333,adapter_ip,7771,
        0,0,0x10,0,0,response,60);
    raw_send(raw,response);
    response_len = create_packet(tmpl,target_ip,30333,adapter_ip,7771,
        0,0,0x11,0,0,response,60);
    raw_send(raw,response);
	return 0;
}

/*tcpcon_send_packet(tcpcon, tcb,
                    0x10, 
                    0, 0);*/