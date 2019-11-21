#pragma once

#define WINDOWS_IGNORE_PACKING_MISMATCH
#pragma pack (1)
typedef struct ether_header {
	unsigned char ether_dhost[6];
	unsigned char ether_shost[6];
	unsigned short ether_type;
}ETHERHEADER, * PETHERHEADER;

typedef struct arp_header {
	unsigned short arp_hrd;
	unsigned short arp_pro;
	unsigned char arp_hln;
	unsigned char arp_pln;
	unsigned short arp_op;
	unsigned char arp_sourha[6];
	unsigned long arp_sourpa;
	unsigned char arp_destha[6];
	unsigned long arp_destpa;
}ARPHEADER, * PARPHEADER;

typedef struct arp_packet {
	ETHERHEADER etherHeader;
	ARPHEADER   arpHeader;
}ARPPACKET, * PARPPACKET;