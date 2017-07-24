#include <pcap.h>
#include <memory.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

struct ether_header *eth;
struct ip *iph;
struct tcphdr *tcph;

/*

	Requirements 
	Ethernet : Destination MAC , Source MAC
	IP 	 : Destination IP  , Source IP
	TCP	 : Destination port, Source port
	Data

*/

void print_eth(const unsigned char *data){
	eth = (struct ether_header *) data;
	
	printf("---------- MAC ----------\n");
	printf("DEST MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                 eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                 eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("SRC  MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		 eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		 eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

}

void print_iph(const unsigned char *data){
	iph = (struct ip *) data;

	char buf[20];

	printf("---------- IP  ----------\n");
	printf("DEST IP  : %s \n", inet_ntop(AF_INET, &(iph->ip_dst), buf, sizeof(buf)));
	printf("SRC  IP  : %s \n", inet_ntop(AF_INET, &(iph->ip_src), buf, sizeof(buf)));
	
}

int main(int argc, char *argv[])
{
	char *dev;         
	char errbuf[PCAP_ERRBUF_SIZE];  
	int i = 0;
	int input = 0;
	
	pcap_if_t *alldevs;
	pcap_if_t *d;
 
	bpf_u_int32 mask;      
	bpf_u_int32 net;     
	struct bpf_program fp;		

	pcap_t *adhandle;
	int ip_res = 0, tcp_res = 0;
	int res;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int count = 0;

	if(argc < 2){
		printf("Need more argument!!\n");
		exit(1);
	}
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
		exit(1);
	}
	
	for (d = alldevs; d; d = d->next){
		printf("%d : %s", ++i, d->name);
		if(d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	input = atoi(argv[1]); 
	printf("input : %d\n", input);

	if(i == 0){
		printf("\nNo interfaces found!\n");
		exit(1);
	}
	
	for ( d = alldevs, i = 0; i < input-1; d = d->next, i++);
	

	if((adhandle = pcap_open_live(d->name, 65536, 1, 0, errbuf)) == NULL){
		printf("[!] Packet descriptor Error!!!\n"); 
		perror(errbuf);
		printf("[!] EXIT process\n");
		pcap_freealldevs(alldevs);
		exit(0);
	}
	
	printf("\nListening on %s...\n", d->name);

	pcap_freealldevs(alldevs);
	
	while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){

		if(res == 0) continue;
		if(count > 9) break;
		printf("\nPacket %d //////////////////////////////\n", count+1);
		print_eth(pkt_data);
		
		if(ntohs(eth->ether_type) == 0x0800){
			pkt_data = pkt_data + sizeof(*eth);
			print_iph(pkt_data);
		}
		else
			printf("It doesn't have IP header!\n");
		
		count++;
	}

	return 0;
}
