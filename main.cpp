#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>

using namespace std;

struct ether_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

#pragma pack(1)
struct arp_header{
    uint16_t hd_type;
    uint16_t prot_type;
    uint8_t hd_size;
    uint8_t prot_size;
    uint16_t opcode;
    uint8_t s_mac[6];
    in_addr s_ip;
    uint8_t t_mac[6];
    in_addr t_ip;
};

#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IP 0x0800
#define HDTYPE_ETH 0x0001
#define MAC_LEN 6
#define IP_LEN 4
#define OP_REQ 0x0001
#define OP_REP 0x0002

void print_mac(uint8_t *p_mac){
    for(int i=0 ; i<MAC_LEN ; i++){
        if(i==5){
            printf("%02x\n",p_mac[i]);
            break;
        }
        printf("%02x:",p_mac[i]);
    }
}

void make_my_mac(char* dev,uint8_t *a_mac){
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, dev);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      //memcpy(a_mac,s.ifr_addr.sa_data,MAC_LEN);
    for (int i = 0; i < 6; i++)
        a_mac[i]=s.ifr_addr.sa_data[i];
  }
}

void make_my_ip (char * dev,in_addr *a_ip) {
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (0 == ioctl(sockfd, SIOCGIFADDR, &ifrq))  {
        //a_ip = a_ip-(char)1;
        sin = (struct sockaddr_in *)&ifrq.ifr_addr;
        memcpy (a_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
    }

}


void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(1){
        uint8_t send_packet[42]={0,};
        uint8_t broadcast[]={"\xff\xff\xff\xff\xff\xff"};
        struct ether_header* s_eth=(struct ether_header*)send_packet;
        memcpy(s_eth->dmac,broadcast,MAC_LEN);
        make_my_mac(dev,s_eth->smac);
        s_eth->type = htons(ETHERTYPE_ARP);

        //---------------------------send_arp_header------------------------

        struct arp_header* s_arp=(struct arp_header*)(send_packet+sizeof (ether_header));
        s_arp->hd_type = htons(HDTYPE_ETH);
        s_arp->prot_type = htons(ETHERTYPE_IP);
        s_arp->hd_size = MAC_LEN;
        s_arp->prot_size = IP_LEN;
        s_arp->opcode = htons(OP_REQ);
        make_my_mac(dev,s_arp->s_mac);
        make_my_ip(dev,&(s_arp->s_ip));
        memset(s_arp->t_mac,'\x00',6);
        inet_aton(argv[2],&(s_arp->t_ip));

        u_char* s_pack = send_packet;
        pcap_sendpacket(handle,s_pack,PCAP_ERRBUF_SIZE);

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ether_header* eth = (struct ether_header*)packet;
        uint16_t eth_type = ntohs(eth->type);

        if(eth_type == ETHERTYPE_ARP ){
            struct arp_header* arph = (struct arp_header*)(packet+sizeof (ether_header));
            uint16_t op=ntohs(arph->opcode);
            if( (op==OP_REP) || (&(s_arp->t_ip) == &(arph->s_ip)) ){
                cout << "-----------------------send_arp_packet------------------" << endl;
                uint8_t send_ak_packet[42]={0,};
                struct ether_header* eth_sap = (ether_header*)send_ak_packet;
                memcpy(eth_sap->dmac,arph->s_mac,MAC_LEN);
                make_my_mac(dev,s_eth->smac);
                s_eth->type = htons(ETHERTYPE_ARP);

                struct arp_header* arp_sap=(struct arp_header*)(send_ak_packet+sizeof (ether_header));
                arp_sap->hd_type = htons(HDTYPE_ETH);
                arp_sap->prot_type = htons(ETHERTYPE_IP);
                arp_sap->hd_size = MAC_LEN;
                arp_sap->opcode = htons(OP_REP);
                make_my_mac(dev,arp_sap->s_mac);
                inet_aton(argv[3],&(arp_sap->s_ip));
                memcpy(arp_sap->t_mac,arph->s_mac,MAC_LEN);
                inet_aton(argv[2],&(arp_sap->t_ip));

                cout << "succes!!!" << endl;
            }

        }
    }


    pcap_close(handle);
    return 0;

}
