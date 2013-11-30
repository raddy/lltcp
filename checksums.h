#ifndef CHECKSUMS_H
#define CHECKSUMS_H
#include <stdio.h>

typedef unsigned long long uint64_t;

unsigned ip_header_checksum(const unsigned char *, unsigned , unsigned );
unsigned tcp_checksum2(const unsigned char *, unsigned , unsigned , size_t );
unsigned tcp_checksum(struct TemplatePacket *);

#endif