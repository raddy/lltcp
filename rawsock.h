#ifndef RAWSOCK_H
#define RAWSOCK_H

unsigned rawsock_get_adapter_ip(const char *ifname);
int rawsock_get_adapter_mac(const char *ifname, unsigned char *mac);
int get_raw_socket(char * device, int protocol);
void read_socket(int , int );
void raw_send(int ,unsigned char * );

#endif