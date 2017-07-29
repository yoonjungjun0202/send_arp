#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
/*
 * netinet/ether.h
 * 		- ether_ntoa()
 * #include <netinet/if_ether.h>
 * #include <linux/if_ether.h>
 * #include <net/ethernet.h>
 *		- struct ether_header
 *		- struct ether_addr
 *		- define ETHERTYPE_ARP = 0x0806
 * 		- define ETHER_ADDR_LEN = 6
 * #include <net/if_arp.h>
 *		- struct ether_arp
 *		- define ARPHRD_ETHER 1
 *		- define ARPOP_REQUEST 1
 */

typedef struct ether_header eth_hdr_t[1];
unsigned char *kStringMacAddressDev = "/sys/class/net/eth0/address";
// unsigned char *kStringMacAddress = "00:1c:42:f1:65:53";

/*
 * pcap_open_live parameter(dev, len, promisc, ms, errbuf)
 * 	- dev    : name of the device
 * 	- len    : portion of the packet to capture (only the first 100 bytes)
 * 	- promisc: promiscuous mode
 * 	- ms     : read timeout
 * 	- errbuf : error buffer
 */
void init_pcap(pcap_t **handle, char *_filter_exp, char *_dev)
{
	char *dev = _dev;           /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
	struct bpf_program fp;      /* The compiled filter */
	bpf_u_int32 mask;       /* Our netmask */
	bpf_u_int32 net;        /* Our IP */


	printf("## init %s....", _dev);

	/* Open the session in promiscuous mode */
	*handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	//  *handle = pcap_open_live("awdl0", BUFSIZ, 1, 1000, errbuf); // dump
	if (*handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(*handle, &fp, _filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", _filter_exp, pcap_geterr(*handle));
		exit(2);
	}

	if (pcap_setfilter(*handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", _filter_exp, pcap_geterr(*handle));
		exit(2);
	}

	printf("complete\n");
}


int get_ether_header(eth_hdr_t _eth_hdr, const u_char *_packet)
{
	struct ether_header *eth_hdr = (struct ether_header *) _packet;
	memcpy(_eth_hdr->ether_dhost, eth_hdr->ether_dhost, sizeof(_eth_hdr->ether_dhost));
	memcpy(_eth_hdr->ether_shost, eth_hdr->ether_shost, sizeof(_eth_hdr->ether_shost));
	_eth_hdr->ether_type = ntohs(eth_hdr->ether_type);

	return sizeof(struct ether_header);
}


u_char *get_mac_address()
{
	FILE *fp = fopen(kStringMacAddressDev, "r");
	int i;
	u_char str_mac_address[ETHER_ADDR_LEN * 3] = {'\0', };
	u_char *mac_address = (u_char *) malloc (ETHER_ADDR_LEN * sizeof(u_char));

	fgets(str_mac_address, ETHER_ADDR_LEN * 3, fp);
	for (i=0; i<ETHER_ADDR_LEN; i++)
		mac_address[i] = strtol(&str_mac_address[i*3], NULL, 16);
//	for (i=0; i<ETHER_ADDR_LEN; i++)
//		mac_address[i] = strtol(&kStringMacAddress[i*3], NULL, 16);
	fclose(fp);
	printf("mac : %s\n", mac_address);

	return mac_address;
}


u_char *get_ip_address(const u_char *_ip)
{

}


/*
 * ether header size: 14 byte
 * ether dst host	:  6 byte
 * ether src host	:  6 byte
 * ether type		:  2 byte
 *
 * arp header size	: 28 byte
 * hardware type	:  2 byte
 * Protocol type	:  2 byte
 * hw addr length	:  1 byte
 * proto addr length:  1 byte
 * opt				:  2 byte	// 1: requset, 2: reply
 * sender mac		:  6 byte
 * sender ip		:  4 byte
 * target mac		:  6 byte
 * target ip		:  4 byte
 */
u_char *create_arp_packet(u_char *_spa, u_char *_tpa)
{
	struct ether_header *eth_hdr = NULL;
	struct ether_arp *arp_hdr = NULL;
	u_char *mac_addr_buf = NULL;
	u_char ip_addr_buf[20] = {'\0', };
	u_char *packet = (u_char *) malloc (sizeof(struct ether_header) + sizeof(struct ether_arp));

	// initialize ether header.
	eth_hdr = (struct ether_header *) packet;
	memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
	mac_addr_buf = get_mac_address();
	memcpy(eth_hdr->ether_shost, mac_addr_buf, ETHER_ADDR_LEN);
	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);

	// initialize arp header.
	arp_hdr = (struct ether_arp *) (packet+sizeof(struct ether_header));
	arp_hdr->ea_hdr.ar_hrd = ntohs(ARPHRD_ETHER);
	arp_hdr->ea_hdr.ar_pro = ntohs(ETHERTYPE_ARP);
	arp_hdr->ea_hdr.ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ea_hdr.ar_pln = 4;
	arp_hdr->ea_hdr.ar_op = ntohs(ARPOP_REQUEST);
	memcpy(arp_hdr->arp_sha, mac_addr_buf, ETHER_ADDR_LEN);
	inet_pton(AF_INET, _spa, ip_addr_buf);
	memcpy(arp_hdr->arp_spa, ip_addr_buf, 4);
	memset(arp_hdr->arp_tha, 0x00, ETHER_ADDR_LEN);
	inet_pton(AF_INET, _tpa, ip_addr_buf);
	memcpy(arp_hdr->arp_tpa, ip_addr_buf, 4);

	free(mac_addr_buf);

	
	printf("## ether info\n");
	printf("dst mac : %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));
	printf("src mac : %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
	printf("type	: %02X\n", eth_hdr->ether_type);
	printf("## arp info\n");
	printf("hw type        : %d\n", arp_hdr->ea_hdr.ar_hrd);
	printf("proto type     : %d\n", arp_hdr->ea_hdr.ar_pro);
	printf("hw addr len    : %d\n", arp_hdr->ea_hdr.ar_hln);
	printf("proto addr len : %d\n", arp_hdr->ea_hdr.ar_pln);
	printf("opt            : %d\n", arp_hdr->ea_hdr.ar_op);
	printf("sender mac     : %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_sha));
	// printf("sender ip      : %s\n", arp_hdr->arp_spa);
	inet_ntop(AF_INET, arp_hdr->arp_spa, ip_addr_buf, sizeof(ip_addr_buf));
	printf("sender ip      : %s\n", ip_addr_buf);
	printf("target mac     : %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_tha));
	// printf("target ip      : %s\n", arp_hdr->arp_tpa);
	inet_ntop(AF_INET, arp_hdr->arp_tpa, ip_addr_buf, sizeof(ip_addr_buf));
	printf("target ip      : %s\n", ip_addr_buf);



	return packet;
}


/*
 * argv[1] : dev
 * argv[2] : source ip
 * argv[3] : target ip
 */
int main(int argc, char *argv[])
{
	pcap_t *handle;         /* Session handle */
	char filter_exp[] = "port 80";  /* The filter expression */
	struct pcap_pkthdr *header; /* The header that pcap gives us */
	const u_char *packet;       /* The actual packet */
	u_char *arp_packet;       /* The actual packet */

	int re, offset;
	eth_hdr_t eth_hdr;
	
	// check input format.
	if(argc < 4)
	{
		printf("Please, check the format as follow:\n");
		printf("./send_arp [interface] [sender ip] [target ip]\n");
		return 0;
	}


	init_pcap(&handle, filter_exp, argv[1]);
	arp_packet = create_arp_packet(argv[2], argv[3]);
	pcap_sendpacket(handle, arp_packet, sizeof(struct ether_header) + sizeof(struct ether_arp));
	free(arp_packet);
/*
	while( 0 <= (re = pcap_next_ex(handle, &header, &packet)) )
	{
		if( 0 == re )
			continue;

		offset = get_ether_header(eth_hdr, packet);
//		printf("ether type: %x\n", (int)eth_hdr->ether_type & 0x0000ffff);
//		printf("ether type: %x\n", ETHERTYPE_IP);
		switch( (int)eth_hdr->ether_type & 0x0000ffff)
		{
			case ETHERTYPE_ARP:
			{
				printf("Ether type : ARP...\n");
				break;
			}
			case ETHERTYPE_IP:
			{
//				printf("Ether type : IP\n");
				break;
			}
			default:
			{
				printf("Ether type : others...\n");
				break;
			}
		}
	}
*/
	pcap_close(handle);


	return(0);
}
