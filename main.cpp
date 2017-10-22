#include <iostream>
#include <string>
#include <stdexcept>

extern "C" {
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <netinet/ip6.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
}

#include "utils.h"
#include "arguments.h"
#include "analyzer.h"
#include "pcap_ptr.h"

using namespace PacketAnalyzer;
using namespace std;

void print_all(Arguments::Parser& ap) {
    // typed options
    for (const auto& s : ap.args())
        if (!s.second.empty())
            cout << s.first << " : " << s.second << '\n';

    // file names
    for (const auto& s : ap.files())  {
        PCAP::PcapPtr pcap {s};
        cout << s << '\n';
    }
}

time_t ToMicroSeconds(const timeval& ts) {
    return 1'000'000UL * ts.tv_sec + ts.tv_usec;
}

int main(int argc, char* argv[]) {
    try {
        Arguments::Parser ap {argc, argv, "ha:s:l:f:"};
        if (Arguments::print_help(ap.get<string>("-h"))) return 1; 
        print_all(ap);

        size_t packetsCount {1};
        for (PCAP::Analyzer a {ap.files()[0]}; a.NextPacket(); ++packetsCount) {
            const auto& header = a.Header();
            const auto* packet = a.Packet();

            cout << packetsCount << ": " << ToMicroSeconds(header.ts) << " " << header.len << " | ";

            const ether_header* eptr {reinterpret_cast<const ether_header*>(packet)};

            const string SrcMAC {ether_ntoa((const ether_addr*)(&eptr->ether_shost))};
            const string DstMAC {ether_ntoa((const ether_addr*)(&eptr->ether_dhost))};

            cout << "Ethernet: " << SrcMAC << " " << DstMAC;

            enum L2Type { IEEE_802_1Q  = 0x8100,
                          IEEE_802_1ad = 0x9100 };

            auto packetType = ntohs(eptr->ether_type);

            switch (packetType) {
                case IEEE_802_1Q:
                {
                    // get VLAN ID
                }
                default: ;
                cout << " | ";
            }

            enum class L3Type { IPv4 = ETHERTYPE_IP, IPv6 = ETHERTYPE_IPV6 };

            switch(static_cast<L3Type>(packetType)) {
                case L3Type::IPv4: 
                {
                    constexpr auto ipOffset {14};

                    ip* packetIP {(ip*)(packet + ipOffset)};

                    const string SrcIP {inet_ntoa(packetIP->ip_src)};
                    const string DstIP {inet_ntoa(packetIP->ip_dst)};

                    cout << "IPv4 ";
                    cout << SrcIP << " "
                         << DstIP << " "
                         << unsigned{packetIP->ip_ttl};

//                    cout <<  packetIP->ip_v << '\n';
                    break;
                }
                case L3Type::IPv6: 
                {
                    constexpr auto ipOffset {14};

                    ip6_hdr* packetIP {(ip6_hdr*)(packet + ipOffset)};

                    char buf[100]{};

                    const string SrcIP {inet_ntop(AF_INET6, (void*)(&packetIP->ip6_src), buf, 100)};
                    const string DstIP {inet_ntop(AF_INET6, (void*)(&packetIP->ip6_dst), buf, 100)};

                    cout << "IPv6 ";
                    cout << SrcIP << " "
                         << DstIP << " "
                         << unsigned{packetIP->ip6_ctlun.ip6_un1.ip6_un1_hlim};
                    break;
                }
                default: ;
            }

            cout << '\n';
        }

    } catch (Arguments::Parser::BadArgsStructure) {
        // no message because getopt writes error by itself
        return 2;
    } catch (Arguments::Parser::BadArgsNum) {
        cerr << "Invalid arguments count!\n";
        return 3;
    } catch (const runtime_error& e) {
        cerr << "Runtime error caught: " << e.what() << '\n';
        return 4;
    }
}
