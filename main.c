#include <stdio.h>
#include <stdlib.h>
#include <linux/if_ether.h>

#include "preprocess.h"
#include "tcpmacros.h"
#include "tcptemplate.h"
#include "rawsock.h"

int main(int argc, char **argv)
{
	char *dev = "eth10gb1";
	char *targ_ip = "10.180.53.102";
	unsigned adapter_ip = rawsock_get_adapter_ip(dev);
	unsigned target_ip = ip_to_int(targ_ip);
	unsigned char adapter_mac[6];
	unsigned char router_mac[6] = {0x00, 0x1c, 0x73, 0x3f, 0xf5, 0x91};
	struct TemplatePacket tmpl[1];
	unsigned hi;

	rawsock_get_adapter_mac(dev, adapter_mac);
    printf( "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    printf( "hardecoded: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            router_mac[0],
            router_mac[1],
            router_mac[2],
            router_mac[3],
            router_mac[4],
            router_mac[5]
            );
	printf("auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (adapter_ip>>24)&0xFF,
            (adapter_ip>>16)&0xFF,
            (adapter_ip>> 8)&0xFF,
            (adapter_ip>> 0)&0xFF
            );
	printf("hardcoded: target-ip=%u.%u.%u.%u\n",
            (target_ip>>24)&0xFF,
            (target_ip>>16)&0xFF,
            (target_ip>> 8)&0xFF,
            (target_ip>> 0)&0xFF
            );
	template_init(tmpl,adapter_mac,router_mac);
	template_target(tmpl,target_ip,30333,adapter_ip,7771,0);
    int raw = get_raw_socket(dev,ETH_P_ALL);
    if (raw==-1){
        printf("Could not open raw socket!\n");
        exit(-1);
    }

    raw_send(raw,tmpl->packet);
    read_socket(raw,5);
	return 0;
}