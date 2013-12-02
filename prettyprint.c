#include "prettyprint.h"

const char * reason_string(int x, char *buffer, size_t sizeof_buffer){
    sprintf(buffer, "%s%s%s%s%s%s%s%s",
        (x&0x01)?"fin-":"",
        (x&0x02)?"syn-":"",
        (x&0x04)?"rst-":"",
        (x&0x08)?"psh-":"",
        (x&0x10)?"ack-":"",
        (x&0x20)?"urg-":"",
        (x&0x40)?"ece-":"",
        (x&0x80)?"cwr-":""
        );
    if (buffer[0] == '\0')
        return "none";
    else
        buffer[strlen(buffer)-1] = '\0';
    return buffer;
}
/*printf( "hardecoded: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
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
            );*/

void mac_string(const char * some_mac){
    printf( "%02x-%02x-%02x-%02x-%02x-%02x\n",
            some_mac[0],
            some_mac[1],
            some_mac[2],
            some_mac[3],
            some_mac[4],
            some_mac[5]
            );
}
void print_ip(const unsigned some_ip){

}