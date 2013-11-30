#include <stdio.h>
#include <stdlib.h>

#include "preprocess.h"
#include "tcpmacros.h"
#include "tcptemplate.h"
#include "iputil.h"

int main(int argc, char **argv){

	char *targ_ip = "10.180.53.102";
	char *adapt_ip = "10.180.53.101";
	unsigned target_ip = ip_to_int(targ_ip);
	unsigned adapter_ip = ip_to_int(adapt_ip);
	unsigned char adapter_mac[6] = {0x00,0x0f,0x53,0x0e,0x75,0x24};
	unsigned char router_mac[6] = {0x00, 0x1c, 0x73, 0x3f, 0xf5, 0x91};
	struct TemplatePacket tmpl[1];
	unsigned char * checkers;
	unsigned calculated_check;

	printf("cool brah\n");
	template_init(tmpl,adapter_mac,router_mac);
	template_target(tmpl,target_ip,30333,adapter_ip,7771,0);
	checkers = get_ip_checksum(tmpl);
	printf("xsum: 0x%x%x \n",checkers[0],checkers[1]);
	calculated_check = ip_header_checksum( tmpl->packet, 
        tmpl->offset_ip, 
        tmpl->length);
	printf("Pack length: %u\n",tmpl->length);
	printf("xsum: 0x%x\n",calculated_check);
	printf("xsum: 0x%x%x\n",(calculated_check>> 8)&0xFF,
            (calculated_check>> 0)&0xFF);
	return 0;
}
