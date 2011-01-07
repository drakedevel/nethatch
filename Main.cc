#include "Logging.hh"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

#include <pcap.h>
#include <libnet.h>

struct LoopUserData
{
    in_addr targetAddr;
    pcap_t *pcap;
    libnet_t *libnet;
};

char libnet_errbuf[LIBNET_ERRBUF_SIZE];
char pcap_errbuf[PCAP_ERRBUF_SIZE];

static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("\t%s <ip> [interface]\n", argv0);
    printf("\n");
    printf("Hatches <ip> on <interface>, or the interface of the default\n");
    printf("route if none is specified.\n");
}

static void PacketHandler(u_char *user, const struct pcap_pkthdr *h,
                          const u_char *bytes);

int main(int argc, char **argv)
{
    const char *target = NULL;
    const char *interface = NULL;

    // Argument handling
    switch (argc) {
    case 3:
        interface = argv[2];
    case 2:
        target = argv[1];
        break;
    default:
        usage(argv[0]);
        return 1;
    }

    // Parse the target address
    in_addr targetAddr;
    int error = inet_pton(AF_INET, target, &targetAddr);
    if (error == 0) {
        ERROR("Error parsing target address '%s'", target);
    }

    printf("%08x\n", *(unsigned int *)&targetAddr);

    // Look up default route if necessary
    if (!interface) {
        WARN("Falling back to eth0 since I don't know routing tables yet.");
        interface = "eth0";
    }

    // Open packet capture on the interface
    pcap_t *pcap = pcap_open_live(interface, 65536, true, 0, pcap_errbuf);
    if (!pcap) {
        ERROR("Error opening interface for capture: %s", pcap_errbuf);
    }

    // Open packet injection on the interface
    libnet_t *libnet = libnet_init(LIBNET_RAW4, (char *)interface, libnet_errbuf);
    if (!libnet) {
        ERROR("Error opening interface for injection: %s", libnet_errbuf);
    }

    // Enter packet loop
    LoopUserData userData = { targetAddr, pcap, libnet };
    pcap_loop(pcap, -1, PacketHandler, (u_char *)&userData);

    return 0;
}

static void InjectRSTs(libnet_t *libnet,
                       libnet_ipv4_hdr *ipv4,
                       libnet_tcp_hdr *tcp)
{
    
}

#ifndef DUMB_AS_NAILS
static void InjectFINs(libnet_t *libnet,
                       libnet_ipv4_hdr *ipv4,
                       libnet_tcp_hdr *tcp)
{
    
}
#endif

static void PacketHandler(u_char *cuser, const struct pcap_pkthdr *h,
                          const u_char *bytes)
{
    LoopUserData *user = (LoopUserData *)cuser;

    if (h->caplen < LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H)
    {
        // Packet chunk too small to contain TCP
        return;
    }
    libnet_ipv4_hdr *ipv4 = (libnet_ipv4_hdr *)(bytes + LIBNET_ETH_H);

    if (memcmp(&ipv4->ip_src, &user->targetAddr, sizeof(user->targetAddr)) &&
        memcmp(&ipv4->ip_dst, &user->targetAddr, sizeof(user->targetAddr)))
    {
        // FIXME: Use a PCAP filter for this
        // Packet is not for us
        return;
    }
    if (ipv4->ip_p != IPPROTO_TCP)
    {
        // FIXME: Use a PCAP filter for this
        // Packet does not contain TCP
        return;
    }
    libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)(bytes + LIBNET_ETH_H + LIBNET_IPV4_H);
        
#ifndef DUMB_AS_NAILS
    if (tcp->th_flags & TH_SYN)
    {
        printf("New connection, sending RSTs.\n");
        InjectRSTs(user->libnet, ipv4, tcp);
    }
    else if (!(tcp->th_flags & TH_FIN) && !(tcp->th_flags & TH_RST))
    {
        printf("Old connection, sending FINs.\n");
        InjectFINs(user->libnet, ipv4, tcp);
    }
#else
    if (!(tcp->th_flags & TH_RST))
    {
        printf("Packet, sending RSTs.\n");
        InjectRSTs(user->libnet, ipv4, tcp);
    }
#endif
}
