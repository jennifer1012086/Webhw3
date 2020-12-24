#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
 
#define BUFSIZE 1514

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

struct ip
{ //IP資料報頭

    u_char Ver_HLen;       //版本+報頭長度
    u_char TOS;            //服務型別
    u_short TotalLen;       //總長度
    u_short ID; //標識
    u_short Flag_Segment;   //標誌+片偏移
    u_char TTL;            //生存週期
    u_char Protocol;       //協議型別
    u_short Checksum;       //頭部校驗和
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding

};


struct tcphdr
{ //TCP資料報頭
    unsigned short SrcPort; //源埠
    unsigned short DstPort; //目的埠
    unsigned long SeqNO; //序號
    unsigned long AckNO; //確認號
    unsigned short HeaderLen; //資料報頭的長度(4 bit) + 保留(4 bit)
    unsigned short Flags; //標識TCP不同的控制訊息
    unsigned short Window; //視窗大小
    unsigned short Checksum; //校驗和
    unsigned short UrgentPointer;  //緊急指標

};

 
struct ether_header
{
	unsigned char ether_dhost[6];	//目的mac
	unsigned char ether_shost[6];	//源mac
	unsigned short ether_type;		//乙太網型別
};

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

 
/*******************************回撥函式************************************/
void ethernet_protocol_callback(unsigned char *argument,const struct pcap_pkthdr \
 *packet_heaher,const unsigned char *packet_content)
{
	unsigned char *mac_string;				//
	struct ether_header *ethernet_protocol;
	unsigned short ethernet_type;			//乙太網型別
    char my_time[200];

    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;

    struct tm *tl = localtime(&((packet_heaher->ts).tv_sec));
    strftime(my_time, sizeof(my_time), "%x %X", tl);

	
    //printf("----------------------------------------------------\n");
    
    printf("%s   ", my_time); //轉換時間
	ethernet_protocol = (struct ether_header *)packet_content;
	
	mac_string = (unsigned char *)ethernet_protocol->ether_shost;//獲取源mac地址
	//printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	printf("%02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	
    mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//獲取目的mac
	//printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	printf("%02x:%02x:%02x:%02x:%02x:%02x  ",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	
	ethernet_type = ntohs(ethernet_protocol->ether_type);//獲得乙太網的型別
    printf("(%#.4x)",ethernet_type);
	
    switch(ethernet_type)
	{
		//case 0x0800:printf("The network layer is IP protocol\n");break;//ip
		case 0x0800:printf("(IPv4)\t");break;//ipv4
        case 0x86dd:printf("(IPv6)\t");break;//ipv6
        default:break;
	}
    
    
    
    if (ethernet_type == 0x0800  ) 
    {
            /* retireve the position of the ip header */
            struct ip *ih = (struct ip*) (packet_content + 14); //length of ethernet header

            /* retireve the position of the udp header */
            u_int ip_len = (ih->Ver_HLen & 0xf) * 4;
            struct udp_header *uh = (struct udp_header*) ((u_char*)ih + ip_len);

            /* convert from network byte order to host byte order */
            u_short  sport = ntohs( uh->sport );
            u_short  dport = ntohs( uh->dport );
            
            tcpHeader = (struct tcphdr*)(packet_content + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->SrcPort);
            destPort = ntohs(tcpHeader->DstPort);

            
            /* print ip addresses and udp ports */
            printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
                ih->saddr.byte1,
                ih->saddr.byte2,
                ih->saddr.byte3,
                ih->saddr.byte4,
                sport,
                ih->daddr.byte1,
                ih->daddr.byte2,
                ih->daddr.byte3,
                ih->daddr.byte4,
                dport);

    }

    /*else if( ethernet_type == 0x86dd )
    {
            struct sockaddr_in6* pt = (struct sockaddr_in6*) (packet_content + 14);
            
            //inet_pton(AF_INET6,  ,&ipv6.addr);
            
            
            printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                (int)pt->sin6_addr.s6_addr[0], (int)pt->sin6_addr.s6_addr[1],
                (int)pt->sin6_addr.s6_addr[2], (int)pt->sin6_addr.s6_addr[3],
                (int)pt->sin6_addr.s6_addr[4], (int)pt->sin6_addr.s6_addr[5],
                (int)pt->sin6_addr.s6_addr[6], (int)pt->sin6_addr.s6_addr[7],
                (int)pt->sin6_addr.s6_addr[8], (int)pt->sin6_addr.s6_addr[9],
                (int)pt->sin6_addr.s6_addr[10], (int)pt->sin6_addr.s6_addr[11],
                (int)pt->sin6_addr.s6_addr[12], (int)pt->sin6_addr.s6_addr[13],
                (int)pt->sin6_addr.s6_addr[14], (int)pt->sin6_addr.s6_addr[15]);
    }*/

  printf("\n");

}
 
int main(int argc, char *argv[])
{
	unsigned char *mac_string;				
	unsigned short ethernet_type;			//乙太網型別

	struct pcap_pkthdr protocol_header;
	struct ether_header *ethernet_protocol;
	
    
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = pcap_open_offline(argv[1], errbuff);
		
	if(pcap_loop(pcap_handle,-1,ethernet_protocol_callback,NULL) < 0)
	{
		perror("pcap_loop");
	}
	
	pcap_close(pcap_handle);
	return 0;
}
