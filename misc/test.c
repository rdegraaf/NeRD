#include <linux/netfilter.h>
#include <libipq.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// old versions of linux/netfilter.h don't define NF_STOP
#ifndef NF_STOP
    #define NF_STOP 5
#endif

u_int16_t ip_checksum(u_int32_t init, const u_int8_t* buf, size_t len)
{
    u_int32_t sum = init;
    u_int16_t* shorts = (u_int16_t*)buf;

    while (len > 1)
    {
        sum += *shorts++;
        len -= 2;
    }

    if (len == 1)
        sum += *(u_int8_t*)shorts;

    while (sum >> 16)	
        sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

u_int16_t tcp_checksum(const struct iphdr* iph, const struct tcphdr* tcph, size_t len)
{
    u_int32_t cksum = 0;
    
    cksum += (iph->saddr >> 16) & 0x0000ffff;
    cksum += iph->saddr & 0x0000ffff;
    cksum += (iph->daddr >> 16) & 0x0000ffff;
    cksum += iph->daddr & 0x0000ffff;
    cksum += htons(iph->protocol & 0x00ff);
    cksum += htons(len);
    return ip_checksum(cksum, (unsigned char*)tcph, len);
}


int handle_packet(unsigned char* pkt, size_t len)
{
    struct iphdr* iph = (struct iphdr*) pkt;
    struct tcphdr* tcph = (struct tcphdr*)(pkt+iph->ihl*4);
    
    if ((iph->daddr == htonl(0x0a010101)) && (tcph->dest == htons(123)))
    {
        printf("forward\n");
        iph->daddr = htonl(0x7f000001);
        tcph->dest = htons(22);
        
        iph->check = 0;
        iph->check = ip_checksum(0, pkt, iph->ihl*4);
        tcph->check = 0;
        tcph->check = tcp_checksum(iph, tcph, len-(iph->ihl*4));
        return NF_ACCEPT;
    }
    else if ((iph->saddr == htonl(0x7f000001)) && (tcph->source == htons(22)))
    {
        printf("reverse\n");
        iph->saddr = htonl(0x0a010101);
        tcph->source = htons(123);
        
        iph->check = 0;
        iph->check = ip_checksum(0, pkt, iph->ihl*4);
        tcph->check = 0;
        tcph->check = tcp_checksum(iph, tcph, len-(iph->ihl*4));
        return NF_STOP;
    }
    else
    {
        printf("wrong packet!\n");
        return NF_ACCEPT;
    }
}

int main()
{
    struct ipq_handle* handle;
    unsigned char buf[10000];
    ipq_packet_msg_t* pkt;
    int verdict;
    
    handle = ipq_create_handle(0, PF_INET);
    ipq_set_mode(handle, IPQ_COPY_PACKET, 65535);
    
    while (1)
    {
        ipq_read(handle, buf, 10000, 0);
        pkt = ipq_get_packet(buf);
        verdict = handle_packet(pkt->payload, pkt->data_len);
        ipq_set_verdict(handle, pkt->packet_id, verdict, pkt->data_len, pkt->payload);
    }
    
    ipq_destroy_handle(handle);
    return 0;
}
