#include <stdio.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include "preprocess.h"
#include "tcpmacros.h"
#include "tcptemplate.h"
#include "rawsock.h"


char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

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
    size_t response_len,payloadlen;
    unsigned char response[2048];
    unsigned seq_them;
    char *payload, *url, *directory, *filename;

	rawsock_get_adapter_mac(dev, adapter_mac);
    
    
	template_init(tmpl,adapter_mac,router_mac);
	template_target(tmpl,target_ip,30333,adapter_ip,7771,0);
    int raw = get_raw_socket(dev,ETH_P_ALL);
    if (raw==-1){
        printf("Could not open raw socket!\n");
        exit(-1);
    }

    raw_send(raw,tmpl->packet);
    while (seq_them<0){ //spin till syn-ack
        sock_len = read_socket(raw,packet_buffer); //grabs 1 packet
        seq_them = parse_raw((u_char *)packet_buffer,(int)sock_len);
    }
    response_len = create_packet(tmpl,target_ip,30333,adapter_ip,7771,
        1,seq_them+1,0x10,0,0,response,60);
    raw_send(raw,response);

    //temporary way of doing payload quickly
    payload = allocate_strmem (2048);
    url = allocate_strmem (40);
    directory = allocate_strmem (80);
    filename = allocate_strmem (80);

    // Set TCP data.
    strcpy (url, "www.google.com");  // Could be URL or IPv4 address
    strcpy (directory, "/");
    strcpy (filename, "filename");
    sprintf (payload, "GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n", directory, filename, url);
    payloadlen = strlen (payload);

    //TRY WITH PUSH
    response_len = create_packet(tmpl,target_ip,30333,adapter_ip,7771,
        1,seq_them+1,0x18,payload,payloadlen,response,sizeof(response));

    //kill connection
    response_len = create_packet(tmpl,target_ip,30333,adapter_ip,7771,
        1+payloadlen,seq_them+1,0x11,0,0,response,60);
    raw_send(raw,response);
	return 0;
}

/*tcpcon_send_packet(tcpcon, tcb,
                    0x10, 
                    0, 0);*/