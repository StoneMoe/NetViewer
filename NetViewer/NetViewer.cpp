#include "headers.h"
#include "tcptable.h"

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)

#define MAXBUF              WINDIVERT_MTU_MAX

#define IF_NOT_END_OF_ARGS(x) if (i + 1 < argc) {x
#define ELSE_ERR(x) }else{std::cerr << x << std::endl;exit(1);}

static void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <option(s)> SOURCES"
        << "Options:\n"
        << "\t-v\t\tverbose level(1,2,3,4)\n"
        << "\t-h\t\tprint as hex\n"
        << "\t-a\t\tprint as ascii\n"
        << "\t-t\t\tuse tree mode instead of scroll mode\n"
        << "\t-d\t\tenable deep packet inspecting\n"
        << std::endl;
}

extern double lastTreePaintTime;
static void paintTree(std::map<std::string, std::set<std::string>> tree) {
    auto now = GET_NOW();
    if (now - lastTreePaintTime < 0.5) {
        return;
    }
    std::cout << "\033[2J\033[1;1H";
    for (auto const& [procName, dsts] : tree)
    {
        std::cout << " - " << procName << std::endl;
        for (auto const& dst : dsts)
        {
            std::cout << '\t' << dst <<std::endl;
        }
    }
    lastTreePaintTime = GET_NOW();
}

int __cdecl main(int argc, char** argv) {
    // arguments
    INT16 verboseLevel = 0;
    bool printAscii = false;
    bool printHex = false;
    bool treeMode = true;
    bool dpiMode = true;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-h") || (arg == "--help")) {
            show_usage(argv[0]);
            return 0;
        }
        else if (arg == "-v") {
            IF_NOT_END_OF_ARGS(std::stoi(argv[i + 1]));
            ELSE_ERR("verbose option need a integer level(1,2,3,4)");
        }
        else if (arg == "-a") {
            printAscii = true;
        } 
        else if (arg == "-h") {
            printHex = true;
        } 
        else if (arg == "-t") {
            treeMode = true;
        } 
        else if (arg == "-d") {
            dpiMode = true;
        } 
        else {
            show_usage(argv[0]);
            return 0;
        }
    }

    // divert config
    INT16 priority = 0;

    // init
    Tabler* tabler = new Tabler();
    tabler->initTcpTable();
    // console
    HANDLE handle, console;
    // parse
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    // compute
    UINT32 src_addr[4], dst_addr[4];
    UINT64 hash;
    char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];
    const char* err_str;
    LARGE_INTEGER base, freq;
    double time_passed;
    // print
    std::map<std::string, std::set<std::string>> tree;
    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    // Divert traffic matching the filter:
    const char* filter = "outbound and tcp";
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_FRAGMENTS);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER && !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    // Max-out the packet queue:
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue length (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue time (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue size (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Set up timing:
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&base);

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
            NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            NULL, NULL, NULL);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            fprintf(stderr, "warning: junk packet\n");
        }

        // Dump packet info.
        if (verboseLevel >= 4)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            time_passed = (double)(addr.Timestamp - base.QuadPart) / (double)freq.QuadPart;
            hash = WinDivertHelperHashPacket(packet, packet_len, 0);
            printf("Packet [Timestamp=%.8g, Direction=%s IfIdx=%u SubIfIdx=%u Loopback=%u Hash=0x%.16llX]\n",
                time_passed, (addr.Outbound ? "outbound" : "inbound"),
                addr.Network.IfIdx, addr.Network.SubIfIdx, addr.Loopback, hash);
        }
        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));
            if (verboseLevel >= 3)
            {
                SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_RED);
                printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X Reserved=%u DF=%u MF=%u FragOff=%u TTL=%u Protocol=%u Checksum=0x%.4X SrcAddr=%s DstAddr=%s]\n",
                    ip_header->Version, ip_header->HdrLength,
                    ntohs(ip_header->TOS), ntohs(ip_header->Length),
                    ntohs(ip_header->Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
                    WINDIVERT_IPHDR_GET_DF(ip_header),
                    WINDIVERT_IPHDR_GET_MF(ip_header),
                    ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header->TTL,
                    ip_header->Protocol, ntohs(ip_header->Checksum), src_str,
                    dst_str);
            }
            
        }
        if (ipv6_header != NULL)
        {
            WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
            WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
            WinDivertHelperFormatIPv6Address(src_addr, src_str, sizeof(src_str));
            WinDivertHelperFormatIPv6Address(dst_addr, dst_str, sizeof(dst_str));
            if (verboseLevel >= 3)
            {
                SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_RED);
                printf("IPv6 [Version=%u TrafficClass=%u FlowLabel=%u Length=%u NextHdr=%u HopLimit=%u SrcAddr=%s DstAddr=%s]\n",
                    ipv6_header->Version,
                    WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
                    ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
                    ntohs(ipv6_header->Length), ipv6_header->NextHdr,
                    ipv6_header->HopLimit, src_str, dst_str);
            }
        }
        if (tcp_header != NULL)
        {
            if (verboseLevel >= 2)
            {
                SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u "
                    "HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
                    "Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
                    "UrgPtr=%u]\n",
                    ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
                    ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
                    tcp_header->HdrLength, tcp_header->Reserved1,
                    tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
                    tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
                    tcp_header->Fin, ntohs(tcp_header->Window),
                    ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
            }
        }

        // Print packet's flow
        std::stringstream ss;
        std::string processName = tabler->queryProcessNameByFlow(ip_header->SrcAddr, ip_header->DstAddr, tcp_header->SrcPort, tcp_header->DstPort);
        std::string dst;
        ss << dst_str << ":" << ntohs(tcp_header->DstPort);
        dst = ss.str();
        if (!treeMode)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("[%s] %s:%d -> %s:%d",
                tabler->queryProcessNameByFlow(ip_header->SrcAddr, ip_header->DstAddr, tcp_header->SrcPort, tcp_header->DstPort).c_str(),
                src_str, ntohs(tcp_header->SrcPort),
                dst_str, ntohs(tcp_header->DstPort)
            );
        }
        else {
            if (tree.count(processName)) {
                // existed
                tree[processName].insert(dst);
            } else {
                tree[processName] = { dst };
            }
            paintTree(tree);
        }


        // DPI Detection
        if (dpiMode)
        {
            // TLS - https://tls.ulfheim.net/
            int hdrOffset = ip_header->HdrLength + tcp_header->HdrLength;
            if (packet_len > 2 && packet[hdrOffset + 0] == 0x16 && packet[hdrOffset + 1] == 0x03 && packet[hdrOffset + 2] == 0x01)
            {
                printf(" - TLS Client Hello");
            }
        }

        // print hash
        if (printHex) {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE);
            for (UINT i = 0; i < packet_len; i++)
            {
                if (i % 20 == 0)
                {
                    printf("\n\t");
                }
                printf("%.2X", (UINT8)packet[i]);
            }
        }

        // print char
        if (printAscii)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
            for (UINT i = 0; i < packet_len; i++)
            {
                if (i % 40 == 0)
                {
                    printf("\n\t");
                }
                if (isprint(packet[i]))
                {
                    putchar(packet[i]);
                }
                else
                {
                    putchar('.');
                }
            }
        }
        putchar('\n');
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}
