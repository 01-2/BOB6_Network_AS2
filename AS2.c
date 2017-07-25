#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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

	char buf[INET_ADDRSTRLEN];

	printf("---------- IP  ----------\n");
	printf("DEST IP  : %s \n", inet_ntop(AF_INET, &(iph->ip_dst), buf, sizeof(buf)));
	printf("SRC  IP  : %s \n", inet_ntop(AF_INET, &(iph->ip_src), buf, sizeof(buf)));
	
}

void print_port(const unsigned char *data){
	tcph = (struct tcphdr *) data;
	printf("---------- PORT ----------\n");
	printf("DEST PORT : %d \n", ntohs(tcph->th_dport));
	printf("SRC  PORT : %d \n", ntohs(tcph->th_sport));
	
}

void print_data(const unsigned char *data, int len){

	int count = 1;

	printf("---------- DATA ----------\n");
	printf("0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F\n");
	
	while((count < len) && (count < 33)){
		printf("%02x ", data[count-1]);
		if(count % 16 == 0)
			printf("\n");
		count++;
	}
}

int main(int argc, char *argv[])
{
	char *dev;         
	char errbuf[PCAP_ERRBUF_SIZE];  
	int i = 0;
	int input = 0;
	
	pcap_if_t *alldevs;
	pcap_if_t *d;

	pcap_t *adhandle;
	int ip_res = 0, tcp_res = 0;
	int res;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int count = 0;
	int dataSize = 0;
	
	// checking arguments 
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

	// move device pointer
	for ( d = alldevs, i = 0; i < input-1; d = d->next, i++);
	

	if((adhandle = pcap_open_live(d->name, 65536, 1, 0, errbuf)) == NULL){
		printf("[!] Packet descriptor Error!!!\n"); 
		perror(errbuf);
		printf("[!] EXIT process\n");
		pcap_freealldevs(alldevs);
		exit(0);
	}
	
	printf("\nListening on %s...\n", d->name);
	
	// free all devices
	pcap_freealldevs(alldevs);
	
	// get next packet by using pcap_next_ex function
	while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){

		if(res == 0) continue;
		if(count > 9) break;

		dataSize = 0;
		printf("\nPacket %d //////////////////////////////\n", count+1);
		print_eth(pkt_data);
		
		// check next header is IPv4 header or not
		if(ntohs(eth->ether_type) == ETHERTYPE_IP){
			pkt_data = pkt_data + sizeof(*eth);
			print_iph(pkt_data);
			
			// check next header is TCP header or not 
			if(iph->ip_p == IPPROTO_TCP){
				// calculate TCP header offset
				pkt_data = pkt_data + (iph->ip_hl * 4);
				print_port(pkt_data);
				
				// calculate data offset
				pkt_data = pkt_data + (tcph->th_off*4);
				dataSize = iph->ip_len - (sizeof(*eth)+(iph->ip_hl + tcph->th_off) * 4);
				print_data(pkt_data, dataSize);
				
			}
			else	printf("It doesn't have TCP header!\n");

		}
		else	printf("It doesn't have IP header!\n");

		count++;
	}

	return 0;
}
